"""Learn which domain names map to which IPs by watching traffic (needs root).

Two passive sources, both read from an AF_PACKET socket:
  * DNS answers (UDP source port 53): A/AAAA records -> the name that was asked for
  * TLS ClientHello SNI: the server name a client sends when it opens an HTTPS
    connection, which also covers apps that use DNS-over-HTTPS.

A classic BPF filter runs in the kernel so Python only sees DNS replies and
TCP segments whose payload starts like a TLS handshake record.

    sudo python3 dnssniff.py     # print names as they are learned
"""
import ctypes
import socket
import struct
import threading
import time
from collections import OrderedDict

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
MAX_NAMES_PER_IP = 6
MAX_IPS = 20000


# ---------- tiny cBPF assembler ----------
def _bpf(prog):
    """prog: list of (label|None, code, k, jt_label, jf_label)."""
    labels = {lbl: i for i, (lbl, *_rest) in enumerate(prog) if lbl}
    out = []
    for i, (_, code, k, jt, jf) in enumerate(prog):
        jt_off = labels[jt] - i - 1 if jt else 0
        jf_off = labels[jf] - i - 1 if jf else 0
        out.append(struct.pack("HBBI", code, jt_off, jf_off, k))
    return out


LDB_ABS, LDH_ABS, LDB_IND, LDH_IND, LDX_MSH = 0x30, 0x28, 0x50, 0x48, 0xb1
AND_K, RSH_K, MUL_K, ADD_K, ADD_X, TAX = 0x54, 0x74, 0x24, 0x04, 0x0c, 0x07
JEQ_K, RET_K = 0x15, 0x06

# Offsets are from the network header (SOCK_DGRAM packet socket).
FILTER = _bpf([
    (None,    LDB_ABS, 0,      None, None),
    (None,    AND_K,   0xf0,   None, None),
    (None,    JEQ_K,   0x40,   "v4", None),
    (None,    JEQ_K,   0x60,   "v6", "drop"),
    ("v4",    LDB_ABS, 9,      None, None),       # protocol
    (None,    JEQ_K,   17,     "v4u", None),
    (None,    JEQ_K,   6,      "v4t", "drop"),
    ("v4u",   LDX_MSH, 0,      None, None),       # X = IP header length
    (None,    LDH_IND, 0,      None, None),       # UDP source port
    (None,    JEQ_K,   53,     "ok", "drop"),
    ("v4t",   LDX_MSH, 0,      None, None),
    (None,    LDB_IND, 12,     None, None),       # TCP data offset
    (None,    RSH_K,   4,      None, None),
    (None,    MUL_K,   4,      None, None),
    (None,    ADD_X,   0,      None, None),
    (None,    TAX,     0,      None, None),       # X = start of TCP payload
    (None,    LDB_IND, 0,      None, None),
    (None,    JEQ_K,   0x16,   "ok", "drop"),     # TLS handshake record
    ("v6",    LDB_ABS, 6,      None, None),       # next header (no ext headers)
    (None,    JEQ_K,   17,     "v6u", None),
    (None,    JEQ_K,   6,      "v6t", "drop"),
    ("v6u",   LDH_ABS, 40,     None, None),
    (None,    JEQ_K,   53,     "ok", "drop"),
    ("v6t",   LDB_ABS, 52,     None, None),
    (None,    RSH_K,   4,      None, None),
    (None,    MUL_K,   4,      None, None),
    (None,    ADD_K,   40,     None, None),
    (None,    TAX,     0,      None, None),
    (None,    LDB_IND, 0,      None, None),
    (None,    JEQ_K,   0x16,   "ok", "drop"),
    ("ok",    RET_K,   0x40000, None, None),
    ("drop",  RET_K,   0,      None, None),
])


def _attach_filter(sock):
    buf = ctypes.create_string_buffer(b"".join(FILTER))
    fprog = struct.pack("HL", len(FILTER), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    return buf  # keep alive


# ---------- DNS ----------
def _read_name(msg, off, depth=0):
    labels = []
    while off < len(msg):
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:
            if depth > 10 or off + 1 >= len(msg):
                raise ValueError("bad pointer")
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            name, _ = _read_name(msg, ptr, depth + 1)
            labels.append(name)
            return ".".join(l for l in labels if l), off + 2
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    raise ValueError("truncated name")


def parse_dns(msg):
    """Yield (ip, queried_name) for A/AAAA answers in a DNS response."""
    if len(msg) < 12:
        return
    flags, qd, an = struct.unpack_from("!HHH", msg, 2)
    if not flags & 0x8000 or qd < 1 or an < 1:
        return
    qname, off = _read_name(msg, 12)
    off += 4
    for _ in range(qd - 1):
        _, off = _read_name(msg, off)
        off += 4
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            yield socket.inet_ntop(socket.AF_INET, rdata), qname.lower()
        elif rtype == 28 and rdlen == 16:
            yield socket.inet_ntop(socket.AF_INET6, rdata), qname.lower()


# ---------- TLS SNI ----------
def parse_sni(p):
    """Return the server_name from a TLS ClientHello, or None."""
    if len(p) < 44 or p[0] != 0x16 or p[5] != 0x01:
        return None
    off = 5 + 4 + 2 + 32               # record hdr, handshake hdr, version, random
    off += 1 + p[off]                  # session id
    off += 2 + struct.unpack_from("!H", p, off)[0]   # cipher suites
    off += 1 + p[off]                  # compression methods
    end = off + 2 + struct.unpack_from("!H", p, off)[0]
    off += 2
    while off + 4 <= min(end, len(p)):
        etype, elen = struct.unpack_from("!HH", p, off)
        off += 4
        if etype == 0:  # server_name
            # list len(2) type(1) name len(2) name
            nlen = struct.unpack_from("!H", p, off + 3)[0]
            return p[off + 5:off + 5 + nlen].decode("ascii", "replace").lower()
        off += elen
    return None


# ---------- sniffer ----------
class Sniffer:
    def __init__(self):
        self._names: "OrderedDict[str, OrderedDict[str, str]]" = OrderedDict()
        self._lock = threading.Lock()
        self.error = None
        self.running = False

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
            self._fbuf = _attach_filter(self.sock)
        except PermissionError:
            self.error = "needs root"
            return False
        except OSError as e:
            self.error = str(e)
            return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        return True

    def _learn(self, ip, name, source):
        if not name:
            return
        with self._lock:
            names = self._names.pop(ip, None) or OrderedDict()
            names.pop(name, None)
            names[name] = source           # most recent last
            while len(names) > MAX_NAMES_PER_IP:
                names.popitem(last=False)
            self._names[ip] = names
            while len(self._names) > MAX_IPS:
                self._names.popitem(last=False)

    def names(self, ip):
        """[(name, source)] most recent first."""
        with self._lock:
            n = self._names.get(ip)
            return list(reversed(n.items())) if n else []

    def _loop(self):
        while True:
            try:
                pkt, addr = self.sock.recvfrom(65535)
                self._handle(pkt, addr[1])
            except Exception:
                continue  # malformed packet; keep going

    def _handle(self, pkt, proto):
        if proto == 0x0800:
            ihl = (pkt[0] & 0x0F) * 4
            l4, nh = pkt[ihl:], pkt[9]
            src, dst = socket.inet_ntop(socket.AF_INET, pkt[12:16]), socket.inet_ntop(socket.AF_INET, pkt[16:20])
        elif proto == 0x86DD:
            l4, nh = pkt[40:], pkt[6]
            src, dst = socket.inet_ntop(socket.AF_INET6, pkt[8:24]), socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        else:
            return
        if nh == 17:
            for ip, name in parse_dns(l4[8:]):
                self._learn(ip, name, "dns")
        elif nh == 6:
            doff = (l4[12] >> 4) * 4
            name = parse_sni(l4[doff:])
            if name:
                self._learn(dst, name, "sni")


if __name__ == "__main__":
    s = Sniffer()
    if not s.start():
        raise SystemExit(f"sniffer failed: {s.error}")
    print("listening for DNS answers and TLS SNI (Ctrl+C to stop)")
    seen = {}
    while True:
        time.sleep(1)
        with s._lock:
            snap = {ip: list(n.items()) for ip, n in s._names.items()}
        for ip, names in snap.items():
            if seen.get(ip) != names:
                seen[ip] = names
                print(f"{ip:40} {', '.join(f'{n} ({src})' for n, src in reversed(names))}")
