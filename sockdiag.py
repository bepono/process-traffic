"""Read TCP/UDP sockets straight from the kernel over netlink sock_diag — what `ss` does
internally, without forking a process every sample.

read_sockets() yields the same dicts as collector.parse_ss(). Socket -> process ownership comes
from /proc/<pid>/fd (like `ss -p`), cached by socket inode so the /proc walk only happens when a
socket we haven't seen appears.
"""
import os
import socket
import struct

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
INET_DIAG_INFO = 2
TCP_ESTABLISHED, TCP_SYN_SENT, TCP_CLOSE_WAIT = 1, 2, 8
STATE_NAMES = {TCP_ESTABLISHED: "ESTAB", TCP_SYN_SENT: "SYN-SENT", TCP_CLOSE_WAIT: "CLOSE-WAIT"}
TCP_STATES = (1 << TCP_ESTABLISHED) | (1 << TCP_SYN_SENT) | (1 << TCP_CLOSE_WAIT)
UDP_STATES = 1 << TCP_ESTABLISHED   # connected UDP sockets
MSG = struct.Struct("=BBBBHH16s16sIQIIIII")   # inet_diag_msg (72 bytes; ports big-endian)


def _request(family, proto, states, ext):
    req = struct.pack("=BBBBHH16s16sIQ", family, proto, ext, 0, 0, 0, b"\0" * 16, b"\0" * 16, 0, 0)
    req = req[:4] + struct.pack("=I", states) + req[4:]
    hdr = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 1, 0)
    return hdr + req


_BUF = bytearray(1 << 16)
_VIEW = memoryview(_BUF)


def _dump(sock, family, proto, states, ext):
    sock.send(_request(family, proto, states, ext))
    while True:
        n = sock.recv_into(_BUF)
        data = bytes(_VIEW[:n])
        off = 0
        while off + 16 <= len(data):
            ln, typ, _flags, _seq, _pid = struct.unpack_from("=IHHII", data, off)
            if typ == NLMSG_DONE:
                return
            if typ == NLMSG_ERROR:
                err = struct.unpack_from("=i", data, off + 16)[0]
                raise OSError(-err, os.strerror(-err))
            yield data[off + 16: off + ln]
            off += (ln + 3) & ~3


def _addr(family, raw):
    return socket.inet_ntop(family, raw[:4] if family == socket.AF_INET else raw)


def _norm(ip):
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


def _tcp_info(payload):
    """Pull the fields we use from struct tcp_info (offsets from linux/tcp.h)."""
    n = len(payload)
    u32 = lambda o: struct.unpack_from("=I", payload, o)[0] if o + 4 <= n else None
    u64 = lambda o: struct.unpack_from("=Q", payload, o)[0] if o + 8 <= n else None
    rtt, rttvar, minrtt = u32(68), u32(72), u32(148)
    return {
        "rtt": rtt / 1000 if rtt else None, "rttvar": rttvar / 1000 if rttvar is not None else None,
        "minrtt": minrtt / 1000 if minrtt and minrtt != 0xFFFFFFFF else None,
        "recv": u64(128) or 0, "sent": u64(200), "acked": u64(120) or 0, "retrans": u64(208) or 0,
        "lastrcv": u32(52), "rcvrtt": (u32(92) or 0) / 1000 or None,
    }


class SockDiag:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_SOCK_DIAG)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        self.owner: dict[int, tuple[int, str]] = {}   # inode -> (pid, comm)
        self.comm: dict[int, str] = {}
        self.unowned: set[int] = set()   # inodes we looked for and couldn't see (other users' sockets when not root)
        self.last_scan = 0.0
        self.scans = 0

    def _scan(self):
        """Map socket inodes to (pid, comm) by walking /proc/<pid>/fd."""
        self.scans += 1
        owner, comm = {}, {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            p = int(pid)
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    ino = int(link[8:-1])
                    if ino not in owner:
                        if p not in comm:
                            try:
                                with open(f"/proc/{pid}/comm") as f:
                                    comm[p] = f.read().strip()
                            except OSError:
                                comm[p] = "?"
                        owner[ino] = (p, comm[p])
        self.owner, self.comm = owner, comm

    def raw(self):
        out = []
        for proto, states, ext in ((socket.IPPROTO_TCP, TCP_STATES, 1 << (INET_DIAG_INFO - 1)), (socket.IPPROTO_UDP, UDP_STATES, 0)):
            for fam in (socket.AF_INET, socket.AF_INET6):
                for msg in _dump(self.sock, fam, proto, states, ext):
                    (family, state, timer, retrans, sport, dport, src, dst, _if, _cookie,
                     _exp, _rq, _wq, _uid, inode) = MSG.unpack_from(msg, 0)
                    info = None
                    off = MSG.size
                    while off + 4 <= len(msg):
                        alen, atype = struct.unpack_from("=HH", msg, off)
                        if alen < 4:
                            break
                        if atype == INET_DIAG_INFO:
                            info = msg[off + 4: off + alen]
                        off += (alen + 3) & ~3
                    out.append((proto, family, state, timer, retrans, socket.ntohs(sport), socket.ntohs(dport), src, dst, inode, info))
        return out

    def read(self):
        import time
        raw = self.raw()
        missing = {r[9] for r in raw if r[9] and r[9] not in self.owner}
        new = missing - self.unowned
        # rescan when a socket we've never looked for appears; re-check unowned ones only every 10 s
        if new or (missing and time.monotonic() - self.last_scan > 10):
            self._scan()
            self.last_scan = time.monotonic()
            self.unowned = {i for i in missing if i not in self.owner}
        live = {r[9] for r in raw}
        if len(self.owner) > 4 * len(live) + 256:   # forget closed sockets
            self.owner = {i: o for i, o in self.owner.items() if i in live}
        res = []
        for proto, family, state, timer, retrans, sport, dport, src, dst, inode, info in raw:
            own = self.owner.get(inode)
            if not own or not inode:
                continue
            pid, comm = own
            t = _tcp_info(info) if info else {}
            sent = t.get("sent")
            if sent is None:   # kernels before 4.19 have no bytes_sent: fall back to acked
                sent = t.get("acked", 0)
            res.append({
                "proto": "tcp" if proto == socket.IPPROTO_TCP else "udp",
                "state": STATE_NAMES.get(state, "ESTAB") if proto == socket.IPPROTO_TCP else "ESTAB",
                "proc": comm, "pid": pid,
                "lh": _norm(_addr(family, src)), "lp": str(sport), "ph": _norm(_addr(family, dst)), "pp": str(dport),
                "sent": sent or 0, "recv": t.get("recv", 0), "retrans": t.get("retrans", 0),
                "rtt": t.get("rtt") if state == TCP_ESTABLISHED else None, "rttvar": t.get("rttvar"), "minrtt": t.get("minrtt"),
                "synRetries": retrans if state == TCP_SYN_SENT else 0, "lastrcv": t.get("lastrcv"), "rcvrtt": t.get("rcvrtt"),
            })
        return res


if __name__ == "__main__":
    import json, time
    d = SockDiag()
    t0 = time.perf_counter(); s = d.read(); t1 = time.perf_counter(); s2 = d.read(); t2 = time.perf_counter()
    print(f"{len(s)} sockets; first read {1000 * (t1 - t0):.1f} ms (with /proc scan), cached {1000 * (t2 - t1):.1f} ms")
    for x in s[:6]:
        print(json.dumps(x))
