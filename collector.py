#!/usr/bin/env python3
"""Process Traffic collector: who on this computer talks to whom, how much, how well,
and why it was allowed — plus the controls to stop it.

A background sampler reads the kernel's per-socket TCP counters (`ss -tinpo`),
connected UDP sockets (`ss -uinp`, QUIC — no byte counters), interface counters
(/proc/net/dev), and, when available, the `machine` firewall's grants, DNS log and
drop log. Results are served as JSON to the D3 page on 127.0.0.1 behind a token.

    python3 collector.py                 # serve the page at http://127.0.0.1:8765
    python3 collector.py --once          # print a plain-language report and exit
    python3 collector.py --explain HOST  # explain one host / process and exit
    sudo python3 collector.py ...        # see every user's processes, names, blocks
"""
import argparse
import atexit
import ipaddress
import json
import os
import pwd
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dnssniff  # noqa: E402
import geo  # noqa: E402
import icons  # noqa: E402

VERSION = "1.0.0"
SNIFFER: "dnssniff.Sniffer | None" = None
TOKEN: str | None = None
SELF_PORTS: set[str] = set()
MY_PID = os.getpid()
IS_ROOT = os.geteuid() == 0
DEMO = None   # demo.Scenario when --demo
STATIC = {"/": "index.html", "/index.html": "index.html", "/icon.svg": "icon.svg",
          "/catalog.json": "catalog.json", "/vendor/d3.v7.9.0.min.js": "vendor/d3.v7.9.0.min.js"}

with open(os.path.join(HERE, "catalog.json")) as _f:
    CATALOG = json.load(_f)

ADDR_RE = re.compile(r"^\[?(?P<host>.+?)\]?:(?P<port>\d+|\*)$")
PROC_RE = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')
NUM = {k: re.compile(rf"\b{k}:(\d+)") for k in ("bytes_sent", "bytes_received", "bytes_retrans", "bytes_acked")}
RTT_RE = re.compile(r"\brtt:([\d.]+)/([\d.]+)")
MINRTT_RE = re.compile(r"\bminrtt:([\d.]+)")
RCVRTT_RE = re.compile(r"\brcv_rtt:([\d.]+)")
TIMER_RE = re.compile(r"timer:\((\w+),[^,]*,(\d+)\)")
LASTRCV_RE = re.compile(r"\blastrcv:(\d+)")

# Health rules (also shown in the page's "How this is measured"). Latency is judged against the
# path's own best round trip (min_rtt), so a healthy intercontinental link isn't called slow.
RTT_FAIR_ABS, RTT_POOR_ABS = 300.0, 800.0     # ms: slow on any path
INFL_FAIR, INFL_POOR = (2.5, 50.0), (4.0, 150.0)   # (× best round trip, and at least this many ms above it)
RETR_FAIR, RETR_POOR = 0.03, 0.06              # share of sent bytes that had to be resent
RETR_MIN_RECENT, RETR_MIN_LIFETIME = 500_000, 1_000_000   # bytes sent before the resend share means anything
HEALTH_RULES = (f"Judged per TCP connection from the kernel's smoothed round trip and resent bytes. "
                f"Fair: round trip over {RTT_FAIR_ABS:.0f} ms, or {INFL_FAIR[0]:g}× its own best and {INFL_FAIR[1]:.0f} ms above it, "
                f"or more than {RETR_FAIR:.0%} of data resent. Poor: over {RTT_POOR_ABS:.0f} ms, or {INFL_POOR[0]:g}× its best and "
                f"{INFL_POOR[1]:.0f} ms above it, or more than {RETR_POOR:.0%} resent. Resends are only judged after "
                f"{RETR_MIN_RECENT // 1000} KB were sent over the last 5 samples, and a connection is only called poor if it was already fair at the previous sample. A high share earlier in the connection is noted but not rated. "
                f"Only resends by this computer are visible — loss on downloads happens at the server and can't be seen here. "
                f"Idle connections, connections still being set up, and UDP aren't rated.")
HEALTH_TABLE = [  # shown as a table in "How it's measured"
    ["Good", "within 2.5× its own best, or less than 50 ms above it", f"under {RETR_FAIR:.0%}"],
    ["Fair", "over 300 ms, or 2.5× its best and 50+ ms above it", f"{RETR_FAIR:.0%}–{RETR_POOR:.0%}"],
    ["Poor", "over 800 ms, or 4× its best and 150+ ms above it", f"over {RETR_POOR:.0%}, two samples in a row"],
]
CDN_ORGS = ("fastly", "akamai", "cloudflare", "edgecast", "limelight", "cdn77", "bunny", "stackpath", "level 3",
            "lumen", "zenlayer", "gcore", "cachefly", "imperva")
CLOUD_ORGS = ("google", "amazon", "microsoft", "oracle", "digitalocean", "hetzner", "ovh", "linode", "akamai connected",
              "alibaba", "tencent", "vultr", "scaleway")
# by AS number: first-party networks (e.g. Google AS15169) are NOT clouds; these are
CLOUD_ASNS = {396982, 19527, 16509, 14618, 8987, 31898, 14061, 24940, 16276, 63949, 20473, 12876, 45102, 132203, 8075}
CDN_ASNS = {54113, 13335, 209242, 20940, 16625, 15133, 22822, 60068, 202053, 199524, 30081}
ADVICE = {  # plain advice by catalog service keyword, used when something was refused
    "telemetry": "Telemetry: apps sending usage or error reports. Usually fine to keep blocked; allow it only if an app you rely on stops working.",
    "analytics": "Analytics: usage tracking. Usually fine to keep blocked.",
    "crash": "Crash reporting. Usually fine to keep blocked; developers just won't see crash reports.",
    "remote desktop": "Remote-desktop relay. Keep blocked unless you're using remote desktop right now.",
    "feature flags": "Feature flags / analytics. Usually fine to keep blocked; some apps may fall back to defaults.",
}


# ---------------------------------------------------------------- helpers
def split_addr(s: str):
    m = ADDR_RE.match(s)
    if not m:
        return s, ""
    host = m.group("host").split("%")[0]
    if host.startswith("::ffff:"):
        host = host[7:]
    return host, m.group("port")


def ip_kind(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "lan"
    return "internet"


def plural(n, word, many=None):
    return f"{n} {word if n == 1 else many or word + 's'}"


def is_loopback(ip: str) -> bool:
    return ip_kind(ip) == "loopback"


def suffix_match(name: str | None, domains) -> str | None:
    if not name:
        return None
    name = name.lower().rstrip(".")
    for d in domains:
        d = d.lower().lstrip("*.")
        if name == d or name.endswith("." + d):
            return d
    return None


def service_for(name):
    d = suffix_match(name, CATALOG["services"])
    return CATALOG["services"][d] if d else None


def port_info(port):
    return CATALOG["ports"].get(str(port))


def health_of(rtt, minrtt=None, retr=None):
    """(good|fair|poor|None, reason). None = not enough to judge."""
    level, why = 0, []
    if rtt is not None:
        base = minrtt or rtt
        extra = rtt - base
        if rtt > RTT_POOR_ABS or (rtt > INFL_POOR[0] * base and extra > INFL_POOR[1]):
            level = 2
            why.append(f"round trip {rtt:.0f} ms vs {base:.0f} ms at best")
        elif rtt > RTT_FAIR_ABS or (rtt > INFL_FAIR[0] * base and extra > INFL_FAIR[1]):
            level = 1
            why.append(f"round trip {rtt:.0f} ms vs {base:.0f} ms at best")
    if retr is not None:
        if retr > RETR_POOR:
            level = 2
            why.append(f"{retr:.1%} of uploaded data resent (poor above {RETR_POOR:.0%})")
        elif retr > RETR_FAIR:
            level = max(level, 1)
            why.append(f"{retr:.1%} of uploaded data resent (fair limit {RETR_FAIR:.0%})")
    if rtt is None and retr is None:
        return None, "not measured"
    return ("good", "fair", "poor")[level], ", ".join(why) or "fast and nothing lost"


# ---------------------------------------------------------------- reverse DNS
_ptr_cache: dict[str, str | None] = {}
_ptr_pool = ThreadPoolExecutor(max_workers=4)
_ptr_lock = threading.Lock()


def _resolve(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None
    with _ptr_lock:
        _ptr_cache[ip] = name


def ptr_name(ip):
    with _ptr_lock:
        if ip in _ptr_cache:
            return _ptr_cache[ip]
        _ptr_cache[ip] = None
    _ptr_pool.submit(_resolve, ip)
    return None


# ---------------------------------------------------------------- socket sampling
def parse_ss(text: str, proto: str):
    """Parse `ss -tinpoH state connected` (proto tcp) or `ss -uinpH state established` (udp)."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        head, info = lines[i], ""
        if i + 1 < len(lines) and lines[i + 1][:1].isspace():
            info = lines[i + 1]
            i += 1
        i += 1
        parts = head.split()
        if proto == "tcp":
            if len(parts) < 5:
                continue
            state, local, peer = parts[0], parts[3], parts[4]
        else:
            if len(parts) < 4:
                continue
            state, local, peer = "ESTAB", parts[2], parts[3]
        if state not in ("ESTAB", "SYN-SENT", "CLOSE-WAIT"):
            continue
        pm = PROC_RE.search(head)
        if not pm:
            continue
        lh, lp = split_addr(local)
        ph, pp = split_addr(peer)
        nums = {k: int(m.group(1)) if (m := r.search(info)) else 0 for k, r in NUM.items()}
        rtt = RTT_RE.search(info)
        minrtt = MINRTT_RE.search(info)
        timer = TIMER_RE.search(head)
        lastrcv = LASTRCV_RE.search(info)
        yield {
            "proto": proto, "state": state,
            "proc": pm.group("name"), "pid": int(pm.group("pid")),
            "lh": lh, "lp": lp, "ph": ph, "pp": pp,
            "sent": nums["bytes_sent"], "recv": nums["bytes_received"],
            "retrans": nums["bytes_retrans"],
            "rtt": float(rtt.group(1)) if rtt else None,
            "rttvar": float(rtt.group(2)) if rtt else None,
            "minrtt": float(minrtt.group(1)) if minrtt else None,
            "synRetries": int(timer.group(2)) if timer and state == "SYN-SENT" else 0,
            "lastrcv": int(lastrcv.group(1)) if lastrcv else None,
            "rcvrtt": float(m.group(1)) if (m := RCVRTT_RE.search(info)) else None,
        }


def run(cmd, timeout=5):
    return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout).stdout


_DIAG = None
_DIAG_FAILED = False


def read_sockets():
    """Netlink sock_diag (no fork, ~10x faster); falls back to parsing `ss` if netlink is unavailable."""
    global _DIAG, _DIAG_FAILED
    if DEMO:
        return DEMO.sockets()
    if not _DIAG_FAILED:
        try:
            if _DIAG is None:
                import sockdiag
                _DIAG = sockdiag.SockDiag()
            return _DIAG.read()
        except Exception as e:
            _DIAG_FAILED = True
            print(f"(netlink sock_diag unavailable, using ss: {e})", file=sys.stderr)
    tcp = list(parse_ss(run(["ss", "-tinpoH", "state", "connected"]), "tcp"))
    udp = list(parse_ss(run(["ss", "-uinpH", "state", "established"]), "udp"))
    return tcp + udp


# ---------------------------------------------------------------- process details
class ProcInfo:
    """exe / cmdline / user / systemd unit for a pid, cached until the pid disappears."""

    def __init__(self):
        self.cache: dict[int, dict] = {}

    def get(self, pid):
        if DEMO:
            return DEMO.proc(pid)
        if pid in self.cache:
            return self.cache[pid]
        info = {"pid": pid}
        base = f"/proc/{pid}"
        try:
            with open(f"{base}/cmdline", "rb") as f:
                info["cmd"] = f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:400]
            with open(f"{base}/status") as f:
                st = dict(l.rstrip("\n").split(":\t", 1) for l in f if ":\t" in l)
            uid = int(st.get("Uid", "0").split()[0])
            info["ppid"] = int(st.get("PPid", "0"))
            try:
                info["user"] = pwd.getpwuid(uid).pw_name
            except KeyError:
                info["user"] = str(uid)
            with open(f"{base}/cgroup") as f:
                cg = f.read().strip().split("::", 1)[-1]
            info["cgroup"] = cg
            info["unit"] = cg.rsplit("/", 1)[-1]
            info["start"] = os.stat(base).st_mtime
        except (OSError, ValueError):
            pass
        try:
            info["exe"] = os.readlink(f"{base}/exe")
        except OSError:
            pass
        if info.get("ppid"):
            try:
                with open(f"/proc/{info['ppid']}/comm") as f:
                    info["parent"] = f.read().strip()
            except OSError:
                pass
        self.cache[pid] = info
        return info

    def prune(self, live):
        for pid in list(self.cache):
            if pid not in live:
                del self.cache[pid]


PROCS = ProcInfo()


def unit_app(unit: str | None):
    """app-gnome-firefox-1234.scope -> firefox ; app-com.anthropic.Claude-1.scope -> com.anthropic.Claude"""
    if not unit:
        return None
    m = re.match(r"app-(?:gnome-|flatpak-)?(.+?)(?:-\d+)?\.(?:scope|service)$", unit)
    return m.group(1).replace("\\x2d", "-") if m else None


# ---------------------------------------------------------------- interfaces
class Interfaces:
    def __init__(self):
        self.prev, self.prev_t = {}, None

    @staticmethod
    def default_iface():
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if p[1] == "00000000" and int(p[3], 16) & 2:
                        return p[0], socket.inet_ntoa(int(p[2], 16).to_bytes(4, "little"))
        except (OSError, IndexError, ValueError):
            pass
        return None, None

    def sample(self):
        if DEMO:
            return DEMO.ifaces()
        now = time.time()
        dflt, gw = self.default_iface()
        wifi = {}
        try:
            with open("/proc/net/wireless") as f:
                for line in f.readlines()[2:]:
                    p = line.split()
                    sig = float(p[3].rstrip("."))
                    wifi[p[0].rstrip(":")] = {"quality": float(p[2].rstrip(".")), "signal": sig if -110 <= sig < 0 else None}
        except OSError:
            pass
        out, cur = [], {}
        try:
            with open("/proc/net/dev") as f:
                rows = f.readlines()[2:]
        except OSError:
            rows = []
        dt = now - self.prev_t if self.prev_t else None
        for line in rows:
            name, data = line.split(":", 1)
            name = name.strip()
            if name == "lo":
                continue
            v = [int(x) for x in data.split()]
            c = {"rx": v[0], "rxPk": v[1], "rxErr": v[2], "rxDrop": v[3], "tx": v[8], "txPk": v[9], "txErr": v[10], "txDrop": v[11]}
            cur[name] = c
            p = self.prev.get(name)
            if not p and name != dflt and not c["rx"] and not c["tx"]:
                continue
            ent = {"name": name, "default": name == dflt, **c,
                   "rxRate": max(0, c["rx"] - p["rx"]) / dt if p and dt else 0.0,
                   "txRate": max(0, c["tx"] - p["tx"]) / dt if p and dt else 0.0,
                   "kind": "wifi" if name in wifi or name.startswith(("wl", "wlan")) else
                           "vpn" if name.startswith(("tun", "wg", "tap")) else
                           "virtual" if name.startswith(("docker", "br-", "veth", "virbr")) else "wired"}
            if name in wifi:
                ent["wifi"] = wifi[name]
            if name == dflt:
                ent["gateway"] = gw
            out.append(ent)
        self.prev, self.prev_t = cur, now
        out.sort(key=lambda e: (not e["default"], e["name"]))
        return out


def dns_servers():
    try:
        with open("/etc/resolv.conf") as f:
            return [l.split()[1] for l in f if l.startswith("nameserver")]
    except OSError:
        return []


# ---------------------------------------------------------------- policy: the `machine` firewall
class MachinePolicy:
    """Reads ~/Projects/_machine's runtime state when it's on this box: which domains are
    allowed and why (state.json), which names resolved to which IPs (dnsmasq log, root),
    and which connections the firewall refused (kernel log, root)."""
    STATE = "/run/machine/state.json"
    DNS_LOG = "/run/machine/dns.log"

    def __init__(self):
        self.state, self.state_mtime = None, 0
        self.ip2name: dict[str, list[str]] = {}   # most recent first
        self.dns_pos = 0
        self.blocked: deque = deque(maxlen=300)
        self.lock = threading.Lock()
        self.on_block = None   # callback(event)
        self._journal = None

    @property
    def present(self):
        return os.path.exists(self.STATE)

    def grants(self):
        try:
            m = os.stat(self.STATE).st_mtime
            if m != self.state_mtime:
                with open(self.STATE) as f:
                    self.state = json.load(f)
                self.state_mtime = m
        except (OSError, ValueError):
            self.state = None
        if not self.state:
            return {}
        return self.state.get("grants", {})

    def lockdown(self):
        g = self.grants()
        return bool(self.state and self.state.get("up")) and not (self.state or {}).get("down")

    def grant_for(self, name):
        for gname, g in self.grants().items():
            d = suffix_match(name, g.get("domains", []))
            if d:
                return {"grant": gname, "domain": d, "reason": g.get("reason"), "kind": g.get("kind"),
                        "since": g.get("since"), "until": g.get("expires") or g.get("until")}
        return None

    def read_dns_log(self):
        """Tail dnsmasq's log: 'reply NAME is IP' -> name for IP (root only)."""
        if DEMO:
            return
        try:
            with open(self.DNS_LOG, errors="replace") as f:
                f.seek(0, 2)
                end = f.tell()
                if end < self.dns_pos:
                    self.dns_pos = 0
                f.seek(max(self.dns_pos, end - 4_000_000))
                chunk = f.read()
                self.dns_pos = f.tell()
        except OSError:
            return
        now = time.time()
        for m in re.finditer(r"reply (\S+) is ([0-9a-fA-F:.]+)\s*$", chunk, re.M):
            try:
                ip = str(ipaddress.ip_address(m.group(2)))
            except ValueError:
                continue
            lst = self.ip2name.setdefault(ip, [])
            name = m.group(1)
            if name in lst:
                lst.remove(name)
            lst.insert(0, name)
            del lst[6:]

    def start_journal(self):
        """Follow netfilter log lines (any prefix) for outbound drops. Root only."""
        if DEMO or not IS_ROOT:
            return False
        try:
            self._journal = subprocess.Popen(
                ["journalctl", "-k", "-f", "-n", "300", "-o", "short-unix", "--no-pager", "--grep", r"OUT=\S+ .*DST="],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError:
            return False
        threading.Thread(target=self._follow, daemon=True).start()
        atexit.register(lambda: self._journal and self._journal.terminate())
        return True

    def _follow(self):
        for line in self._journal.stdout:
            ev = parse_drop(line)
            if ev:
                with self.lock:
                    self.blocked.append(ev)
                if self.on_block:
                    self.on_block(ev)

    def set_members(self):
        """{ip: (grant name | "open", seconds left)} from the firewall's live address sets. Root only; cached 4 s."""
        now = time.time()
        if getattr(self, "_sets_t", 0) > now - 4:
            return self._sets
        self._sets_t, self._sets = now, {}
        if not IS_ROOT or DEMO:
            return self._sets
        try:
            data = json.loads(run(["nft", "-j", "list", "table", "inet", "machine"]))
        except (ValueError, OSError, subprocess.SubprocessError):
            return self._sets
        for item in data.get("nftables", []):
            st = item.get("set")
            if not st:
                continue
            m = re.match(r"^g_(.+)_[46]$", st["name"])
            owner = m.group(1) if m else "open" if st["name"] in ("open4", "open6") else None
            if not owner:
                continue
            for e in st.get("elem", []):
                e = e.get("elem", e) if isinstance(e, dict) else e
                val = e.get("val") if isinstance(e, dict) else e
                exp = e.get("expires") if isinstance(e, dict) else None
                if isinstance(val, str):
                    self._sets[val] = (owner, exp)
                elif isinstance(val, dict) and "prefix" in val:
                    self._sets.setdefault("_nets", []).append((ipaddress.ip_network(f"{val['prefix']['addr']}/{val['prefix']['len']}", False), owner, exp))
        return self._sets

    def rule_for_ip(self, ip):
        sets = self.set_members()
        if ip in sets:
            return sets[ip]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, owner, exp in sets.get("_nets", []):
            if a.version == net.version and a in net:
                return owner, exp
        return None

    def recent_blocked(self, seconds=600):
        cut = time.time() - seconds
        with self.lock:
            return [e for e in self.blocked if e["t"] >= cut]


def parse_drop(line: str):
    m = re.match(r"^(\d+(?:\.\d+)?)\s+\S+\s+kernel:\s*(.*)$", line.strip())
    if not m:
        return None
    t, msg = float(m.group(1)), m.group(2)
    if "OUT=" not in msg or "DST=" not in msg:
        return None
    prefix = msg.split("IN=", 1)[0].strip().rstrip(":") or "firewall"
    f = dict(re.findall(r"(\w+)=(\S+)", msg))
    try:
        dst = str(ipaddress.ip_address(f.get("DST", "")))
    except ValueError:
        return None
    uid = f.get("UID")
    try:
        user = pwd.getpwuid(int(uid)).pw_name if uid else None
    except (KeyError, ValueError):
        user = uid
    return {"t": t, "rule": prefix, "ip": dst, "port": f.get("DPT"), "sport": f.get("SPT"), "proto": f.get("PROTO", "").lower(),
            "user": user, "uid": uid, "syn": " SYN " in f" {msg} "}


MACHINE = MachinePolicy()


def enrich_host(n):
    """Service (catalog), network owner (ASN), CDN, TLS evidence, firewall grant."""
    name = n.get("dns")
    svc = service_for(name)
    if svc:
        n["org"], n["service"] = svc
    a = geo.ASN.lookup(n["ip"]) if n["kind"] == "internet" else None
    if a:
        n["asn"], n["netOrg"] = a["asn"], a["org"]
    owner = (n.get("netOrg") or "").lower()
    first_party = bool(n.get("org") and n["org"].lower() in owner)
    asn = n.get("asn")
    n["cdn"] = ((asn in CDN_ASNS or any(c in owner for c in CDN_ORGS)) and not first_party) or \
        bool(name and any(t in name for t in ("cdn", "akamai", "fastly", "cloudfront", "edgesuite")))
    n["hosting"] = "cdn" if n["cdn"] else "cloud" if asn in CLOUD_ASNS and not first_party else None
    if n.get("nameSource") == "sni" or (SNIFFER and any(src == "sni" for _, src in SNIFFER.names(n["ip"]))):
        n["tls"] = "seen"
    g = grant_by_set(n["ip"]) if n["kind"] == "internet" else None
    n["ruleChecked"] = bool(IS_ROOT and MACHINE.present) or bool(DEMO)
    if not g:
        g = grant_lookup(name)
    if not g:
        for alt in n.get("names") or []:
            g = grant_lookup(alt)
            if g:
                break
    # (no guessing a rule from the network owner: Google, Amazon & co. run everything. The exact answer
    #  comes from the firewall's own address sets above, in admin mode.)
    if g:
        n["grant"] = g


def grant_by_owner(net_org):
    """No name known: match the address's network owner (ASN) against the orgs behind each rule's domains."""
    grants = DEMO.policy()["grants"] if DEMO else [dict(v, name=k) for k, v in MACHINE.grants().items()] if MACHINE.present else []
    low = net_org.lower()
    for g in grants:
        for d in g.get("domains", []):
            svc = CATALOG["services"].get(d)
            if svc and svc[0].lower() in low:
                return {"grant": g["name"], "domain": d, "reason": g.get("reason"), "kind": g.get("kind"),
                        "since": g.get("since"), "until": g.get("until"), "via": "network owner", "_svc": svc}
    return None


def grant_by_set(ip):
    """Exact: which rule's live address set contains this IP (the firewall's own answer)."""
    if DEMO:
        r = DEMO.rule_for_ip(ip)
    else:
        r = MACHINE.rule_for_ip(ip) if MACHINE.present else None
    if not r:
        return None
    owner, exp = r
    if owner == "open":
        return {"grant": "open", "domain": "everything", "reason": "the firewall is temporarily open", "kind": "open", "via": "set", "expires": exp}
    gs = DEMO.policy()["grants"] if DEMO else [dict(v, name=k) for k, v in MACHINE.grants().items()]
    g = next((g for g in gs if g["name"] == owner), {"name": owner})
    return {"grant": owner, "domain": ", ".join(g.get("domains", [])[:3]), "reason": g.get("reason"), "kind": g.get("kind"),
            "since": g.get("since"), "until": g.get("expires") or g.get("until"), "via": "set", "expires": exp}


def grant_lookup(name):
    if DEMO:
        for g in DEMO.policy()["grants"]:
            d = suffix_match(name, g["domains"])
            if d:
                return {"grant": g["name"], "domain": d, "reason": g["reason"], "kind": g["kind"],
                        "since": g.get("since"), "until": g.get("expires") or g.get("until")}
        return None
    return MACHINE.grant_for(name) if MACHINE.present else None


# ---------------------------------------------------------------- control (root)
class Control:
    """Session blocks in our own nftables table `inet process_traffic` (removed on exit),
    cutting live TCP connections with `ss -K`, and `machine allow/revoke` when present."""
    TABLE = "process_traffic"

    def __init__(self):
        self.blocks: dict[str, dict] = {}   # id -> {kind, target, label, since, rules?}
        self.ready = False
        self.error = None
        self.lock = threading.Lock()

    @property
    def available(self):
        return IS_ROOT or bool(DEMO)

    def nft(self, script):
        p = subprocess.run(["nft", "-e", "-a", "-f", "-"], input=script, capture_output=True, text=True)
        if p.returncode:
            raise RuntimeError(p.stderr.strip() or "nft failed")
        return p.stdout

    def setup(self):
        if self.ready or DEMO:
            self.ready = True
            return
        self.nft(f"""table inet {self.TABLE} {{
  set b4 {{ type ipv4_addr; flags interval; }}
  set b6 {{ type ipv6_addr; flags interval; }}
  chain out {{ type filter hook output priority -10; policy accept;
    ip daddr @b4 counter reject comment "pt:hosts4"
    ip6 daddr @b6 counter reject comment "pt:hosts6"
  }}
}}""")
        self.ready = True
        atexit.register(self.teardown)

    def teardown(self):
        if self.ready and not DEMO:
            subprocess.run(["nft", "delete", "table", "inet", self.TABLE], capture_output=True)
            self.ready = False

    def counters(self):
        """packets refused per block, from nft counters."""
        if DEMO or not self.ready or not self.blocks:
            return {}
        try:
            data = json.loads(run(["nft", "-j", "list", "table", "inet", self.TABLE]))
        except ValueError:
            return {}
        out = {}
        for item in data.get("nftables", []):
            r = item.get("rule")
            if not r:
                continue
            c = next((e["counter"] for e in r.get("expr", []) if "counter" in e), None)
            if c and r.get("comment", "").startswith("pt:"):
                out[r["comment"][3:]] = c["packets"]
        return out

    def kill(self, match):
        """Cut live TCP connections matching (pid?, ip?, port?)."""
        n = 0
        for s in read_sockets():
            if s["proto"] != "tcp":
                continue
            if match.get("pid") and s["pid"] not in match["pids"]:
                continue
            if match.get("ip") and s["ph"] != match["ip"]:
                continue
            if not DEMO:
                subprocess.run(["ss", "-K", "src", s["lh"], "sport", "=", f":{s['lp']}",
                                "dst", s["ph"], "dport", "=", f":{s['pp']}"], capture_output=True)
            n += 1
        return n

    def block_host(self, ip, label):
        ip = str(ipaddress.ip_address(ip))
        self.setup()
        fam = "b4" if ":" not in ip else "b6"
        if not DEMO:
            self.nft(f"add element inet {self.TABLE} {fam} {{ {ip} }}")
        bid = f"host:{ip}"
        with self.lock:
            self.blocks[bid] = {"id": bid, "kind": "host", "ip": ip, "label": label, "since": time.time()}
        cut = self.kill({"ip": ip})
        return {"blocked": bid, "cut": cut}

    def unblock_host(self, ip):
        fam = "b4" if ":" not in ip else "b6"
        if not DEMO:
            self.nft(f"delete element inet {self.TABLE} {fam} {{ {ip} }}")
        with self.lock:
            self.blocks.pop(f"host:{ip}", None)
        return {"unblocked": ip}

    def block_app(self, pid, label, app_key):
        """Block an app by its systemd scope (cgroup); new scopes of the same app (it restarted)
        are blocked too, by enforce() on every sample, until unblocked."""
        info = PROCS.get(pid)
        cg = info.get("cgroup")
        if not cg or cg == "/":
            raise RuntimeError("this process has no app scope to block")
        if "/session-" in cg or cg.endswith(("init.scope", "user@1000.service")) or not unit_app(info.get("unit")):
            raise RuntimeError(f"refusing to block {cg}: it isn't a single app's scope (it may hold your whole login session)")
        self.setup()
        bid = f"app:{app_key}"
        with self.lock:
            self.blocks[bid] = {"id": bid, "kind": "app", "app": app_key, "label": label, "since": time.time(),
                                "rules": {}, "unit": info.get("unit")}
        self._block_cgroup(bid, cg)
        cut = self.kill({"pid": True, "pids": self.pids_in_cgroup(cg)})
        return {"blocked": bid, "cut": cut}

    def _block_cgroup(self, bid, cg):
        b = self.blocks[bid]
        if cg in b["rules"]:
            return
        handle = None
        if not DEMO:
            level = cg.strip("/").count("/") + 1
            out = self.nft(f'add rule inet {self.TABLE} out socket cgroupv2 level {level} "{cg.strip("/")}" '
                           f'counter reject comment "pt:{bid}"')
            m = re.search(r"# handle (\d+)", out)
            handle = int(m.group(1)) if m else None
        b["rules"][cg] = handle

    def enforce(self, procs):
        """procs: {app_key: set(cgroups)} seen this sample."""
        for b in list(self.blocks.values()):
            if b["kind"] == "app":
                for cg in procs.get(b["app"], ()):
                    if cg not in b["rules"]:
                        try:
                            self._block_cgroup(b["id"], cg)
                            self.kill({"pid": True, "pids": self.pids_in_cgroup(cg)})
                        except Exception as e:
                            self.error = str(e)

    @staticmethod
    def pids_in_cgroup(cg):
        if DEMO:
            return DEMO.pids_in(cg)
        try:
            with open(f"/sys/fs/cgroup{cg}/cgroup.procs") as f:
                return {int(x) for x in f.read().split()}
        except OSError:
            return set()

    def unblock(self, bid):
        b = self.blocks.get(bid)
        if not b:
            return {"error": "no such block"}
        if b["kind"] == "host":
            return self.unblock_host(b["ip"])
        if not DEMO:
            for handle in (b.get("rules") or {}).values():
                if handle is not None:
                    try:
                        self.nft(f"delete rule inet {self.TABLE} out handle {handle}")
                    except RuntimeError:
                        pass   # scope already gone
        with self.lock:
            self.blocks.pop(bid, None)
        return {"unblocked": bid}

    def machine(self, args):
        if DEMO:
            return {"ok": True, "demo": True, "cmd": ["machine", *args]}
        exe = "/usr/local/bin/machine" if os.path.exists("/usr/local/bin/machine") else "machine"
        p = subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)
        return {"ok": p.returncode == 0, "out": (p.stdout + p.stderr).strip()[-2000:]}


CONTROL = Control()


# ---------------------------------------------------------------- sampler
class Sampler:
    """Samples on its own clock so any number of viewers cost one `ss` per interval."""

    def __init__(self, interval=2.0):
        self.interval = interval
        self.prev: dict[tuple, tuple] = {}
        self.prev_t = None
        self.lock = threading.Lock()
        self.snapshot = None
        self.history = deque(maxlen=180)     # (t, out, in, ifaceOut, ifaceIn) — 6 min at 2 s
        self.events = deque(maxlen=500)
        self.event_seq = 0
        self._snap_json = None
        self.seen_links: dict[tuple, float] = {}
        self.link_health: dict[tuple, str] = {}
        self.ifaces = Interfaces()
        self.coverage = None                  # EWMA share of interface bytes we can attribute
        self.seq = 0
        self.self_traffic = {}                # client label -> [bytes_out, bytes_in, requests]
        self.self_lock = threading.Lock()
        self.timing = deque(maxlen=60)
        self.first_seen: dict[str, float] = {}
        self.retr_win: dict[tuple, deque] = {}
        self.acc: dict[str, list] = {}      # node/link key -> [bytes out, bytes in] since monitoring started
        self.preexisting: set = set()
        self.started = time.time()
        MACHINE.on_block = self._on_block

    # ---- events
    def event(self, kind, text, **kw):
        if getattr(self, "actor", None) and "actor" not in kw:
            kw["actor"] = self.actor
        self.event_seq += 1
        self.events.append({"t": time.time(), "kind": kind, "text": text, "seq": self.event_seq, **kw})

    def _attribute(self, ev):
        """Find the app behind a logged refusal by its source port, if the socket is still around (a dropped SYN
        keeps retrying for seconds; a rejected one dies at once)."""
        try:
            for s in read_sockets():
                if s["proto"] == ev["proto"] and s["ph"] == ev["ip"] and s["lp"] == ev.get("sport"):
                    return s["proc"], s["pid"]
        except Exception:
            pass
        return None

    def _on_block(self, ev):
        who = self._attribute(ev)
        if who:
            ev["app"], ev["pid"] = who
        name = self.name_for(ev["ip"])[0]
        who = f" (user {ev['user']})" if ev.get("user") else ""
        self.event("blocked", f"Firewall refused {name or ev['ip']}:{ev['port'] or '?'}{who}",
                   host=f"h:{ev['ip']}", ip=ev["ip"])

    def note_self(self, label, out_b, in_b):
        with self.self_lock:
            t = self.self_traffic.setdefault(label, [0, 0, 0])
            t[0] += out_b; t[1] += in_b; t[2] += 1

    # ---- names
    def name_for(self, ip):
        """(name, source, all names) — captured DNS/SNI > resolver log > reverse DNS."""
        seen = SNIFFER.names(ip) if SNIFFER else []
        if DEMO:
            n = DEMO.name(ip)
            return (n, "dns", [n]) if n else (None, None, [])
        if seen:
            return seen[0][0], seen[0][1], [n for n, _ in seen]
        r = MACHINE.ip2name.get(ip)
        if r:
            return r[0], "resolver", list(r)
        p = ptr_name(ip)
        return (p, "ptr", [p]) if p else (None, None, [])

    # ---- main loop
    def loop(self):
        while True:
            t0 = time.time()
            try:
                self.sample()
            except Exception as e:  # never let the sampler die
                print(f"sample failed: {e!r}", file=sys.stderr)
            time.sleep(max(0.2, self.interval - (time.time() - t0)))

    def start(self):
        self.sample()
        threading.Thread(target=self.loop, daemon=True).start()

    def sample(self):
        t_start = time.perf_counter()
        with self.lock:
            now = time.time()
            dt = (now - self.prev_t) if self.prev_t else None
            socks = read_sockets()
            t_ss = time.perf_counter()
            if IS_ROOT:
                MACHINE.read_dns_log()
            ifaces = self.ifaces.sample()
            local_owner = {(s["lh"], s["lp"]): s for s in socks}

            nodes, links, cur, seen_pairs = {}, {}, {}, set()

            def proc_node(s):
                if s["pid"] == MY_PID and s["lp"] in SELF_PORTS:
                    return None  # our own API connections: accounted from the server side instead
                if s["pp"] in SELF_PORTS and is_loopback(s["ph"]):
                    return None
                nid = f"p:{s['proc']}"
                n = nodes.get(nid)
                if not n:
                    n = nodes[nid] = {"id": nid, "type": "process", "label": s["proc"], "pids": set(),
                                      "users": set(), "units": set(), "sent": 0, "recv": 0,
                                      "rateOut": 0.0, "rateIn": 0.0, "conns": 0}
                    desc = CATALOG["processes"].get(s["proc"])
                    if desc:
                        n["desc"] = desc
                if s["pid"] not in n["pids"]:
                    n["pids"].add(s["pid"])
                    info = PROCS.get(s["pid"])
                    if info.get("user"):
                        n["users"].add(info["user"])
                    if info.get("unit"):
                        n["units"].add(info["unit"])
                    for k in ("exe", "parent"):
                        if info.get(k) and k not in n:
                            n[k] = info[k]
                    if info.get("cmd") and "cmd" not in n:
                        n["cmd"] = info["cmd"][:160]
                return n

            def host_node(s):
                tid = f"h:{s['ph']}"
                n = nodes.get(tid)
                if n:
                    return n
                kind = ip_kind(s["ph"])
                name, src, names = self.name_for(s["ph"]) if kind != "loopback" else (None, None, [])
                n = nodes[tid] = {"id": tid, "type": "host", "label": s["ph"], "ip": s["ph"], "kind": kind,
                                  "ports": set(), "protos": set(), "sent": 0, "recv": 0,
                                  "rateOut": 0.0, "rateIn": 0.0, "cc": geo.DB.lookup(s["ph"]),
                                  "dns": name, "nameSource": src, "names": names}
                enrich_host(n)
                return n

            for s in socks:
                key = (s["proto"], s["pid"], s["lh"], s["lp"], s["ph"], s["pp"])
                cur[key] = (s["sent"], s["recv"], s["retrans"])
                d_sent = d_recv = d_retr = 0
                if dt and key in self.prev:
                    ps, pr, pt = self.prev[key]
                    d_sent, d_recv, d_retr = max(0, s["sent"] - ps), max(0, s["recv"] - pr), max(0, s["retrans"] - pt)
                elif dt:
                    d_sent, d_recv, d_retr = s["sent"], s["recv"], s["retrans"]
                rate_out = d_sent / dt if dt else 0.0
                rate_in = d_recv / dt if dt else 0.0

                src = proc_node(s)
                if src is None:
                    continue
                peer = local_owner.get((s["ph"], s["pp"])) if is_loopback(s["ph"]) else None
                if peer:
                    pair = tuple(sorted([(s["lh"], s["lp"]), (s["ph"], s["pp"])]))
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    tgt = proc_node(peer)
                    if tgt is None or tgt is src:
                        continue
                else:
                    tgt = host_node(s)
                    tgt["ports"].add(s["pp"])
                    tgt["protos"].add(s["proto"])

                lk = (src["id"], tgt["id"])
                l = links.get(lk)
                if not l:
                    l = links[lk] = {"source": src["id"], "target": tgt["id"], "conns": 0, "connecting": 0,
                                     "protos": set(), "ports": set(), "sent": 0, "recv": 0,
                                     "rateOut": 0.0, "rateIn": 0.0, "_rtt": [], "_minrtt": [],
                                     "_dsent": 0, "_dretr": 0, "_sent": 0, "_retr": 0, "_syn": 0, "pids": set()}
                l["conns"] += 1
                l["pids"].add(s["pid"])
                l["protos"].add(s["proto"]); l["ports"].add(s["pp"])
                if s["state"] == "SYN-SENT":
                    l["connecting"] += 1
                    l["_syn"] = max(l["_syn"], s["synRetries"])
                # only rate latency on connections that moved data recently: idle sockets carry stale,
                # delayed-ACK-inflated round-trip estimates
                active = (d_sent + d_recv) >= 4096   # trickles (keepalives, pings) give meaningless RTTs
                if s["rtt"] is not None and s["state"] == "ESTAB":
                    l["_idle"] = l.get("_idle", True) and not active
                    if active:
                        r_ = s["rtt"]
                        if d_recv > 10 * max(d_sent, 1):
                            # download-only: the send-side RTT is stale and receive-side RTT balloons when the
                            # sender is app-limited (streams), so only trust it on a bulk transfer
                            if s.get("rcvrtt") and d_recv >= 512_000:
                                r_ = s["rcvrtt"]; l["rttKind"] = "receive"
                            else:
                                l["_dlonly"] = True
                                r_ = None
                        if r_ is not None:
                            l["_rtt"].append(r_)
                if s["minrtt"] is not None:
                    l["_minrtt"].append(s["minrtt"])
                l["_dsent"] += d_sent; l["_dretr"] += d_retr
                if self.prev_t:   # only bytes moved while we watched; the first sample's counters predate us
                    for k_, (o_, i_) in ((f"{src['id']}→{tgt['id']}", (d_sent, d_recv)), (src["id"], (d_sent, d_recv)), (tgt["id"], (d_recv, d_sent))):
                        a_ = self.acc.setdefault(k_, [0, 0]); a_[0] += o_; a_[1] += i_
                l["_sent"] += s["sent"]; l["_retr"] += s["retrans"]
                l["sent"] += s["sent"]; l["recv"] += s["recv"]
                l["rateOut"] += rate_out; l["rateIn"] += rate_in
                src["sent"] += s["sent"]; src["recv"] += s["recv"]; src["conns"] += 1
                tgt["sent"] += s["recv"]; tgt["recv"] += s["sent"]
                src["rateOut"] += rate_out; src["rateIn"] += rate_in
                tgt["rateOut"] += rate_in; tgt["rateIn"] += rate_out

            # ---- health per link, rolled up to hosts
            for lk, l in links.items():
                rtts = l.pop("_rtt"); mins = l.pop("_minrtt")
                l["rtt"] = round(sorted(rtts)[len(rtts) // 2], 1) if rtts else None
                l["minRtt"] = round(min(mins), 1) if mins else None
                dsent, dretr, tsent, tretr = l.pop("_dsent"), l.pop("_dretr"), l.pop("_sent"), l.pop("_retr")
                # resends judged over a sliding window of the last 5 samples, and only with enough data:
                # a single loss burst on a small transfer shouldn't flip the rating
                win = self.retr_win.setdefault(lk, deque(maxlen=5))
                win.append((dsent, dretr))
                wsent, wretr = sum(x[0] for x in win), sum(x[1] for x in win)
                if wsent >= RETR_MIN_RECENT:
                    l["retr"], l["retrBasis"] = wretr / wsent, "now"
                elif tsent >= RETR_MIN_LIFETIME:
                    l["retr"], l["retrBasis"] = tretr / tsent, "earlier"
                else:
                    l["retr"], l["retrBasis"] = None, None
                idle = l.pop("_idle", False)
                dlonly = l.pop("_dlonly", False)
                syn = l.pop("_syn")
                l["synRetries"] = syn
                l["health"], l["healthWhy"] = health_of(l["rtt"], l["minRtt"], l["retr"] if l["retrBasis"] == "now" else None)
                # hysteresis: only call it poor if it was already at least fair last time
                if l["health"] == "poor" and self.link_health.get(lk) not in ("fair", "poor"):
                    l["health"] = "fair"
                l["latencyIssue"] = bool(l["rtt"] and l["minRtt"] and l["rtt"] > INFL_FAIR[0] * l["minRtt"] and l["rtt"] - l["minRtt"] > INFL_FAIR[1])
                if l["retrBasis"] == "earlier" and l["retr"] is not None and l["retr"] > RETR_FAIR and l["health"] in ("good", None):
                    l["healthNote"] = f"{l['retr']:.1%} of uploaded data was resent earlier in this connection"
                if idle and l["health"] is None:
                    l["healthWhy"] = "idle — not rated (under 4 KB moved in the last sample)"
                elif dlonly and l["health"] is None:
                    l["healthWhy"] = "download-only stream — not rated (its delay can't be measured reliably from this side)"
                if l["connecting"] and l["connecting"] == l["conns"]:
                    l["health"], l["healthWhy"] = None, ("no reply yet — %s" % plural(syn, "retry", "retries")) if syn else "connecting"
                    l["stalled"] = syn >= 2
                if l["protos"] == {"udp"}:
                    l["health"], l["healthWhy"] = None, "UDP — not measurable"
                l["protos"] = sorted(l["protos"]); l["ports"] = sorted(l["ports"], key=lambda p: int(p) if p.isdigit() else 0)
                l["pids"] = sorted(l["pids"])
                tgt = nodes[l["target"]]
                if tgt["type"] == "host":
                    rank = {"poor": 3, "fair": 2, "good": 1, None: 0}
                    if rank[l["health"]] > rank[tgt.get("health")]:
                        tgt["health"] = l["health"]
                    if l["rtt"] is not None:
                        tgt["rtt"] = min(tgt.get("rtt") or 1e9, l["rtt"])
                    tgt["connecting"] = tgt.get("connecting", 0) + l["connecting"]
                    if l.get("stalled"):
                        tgt["stalled"] = True
                    if any(p in ("80", "8080", "21", "23", "143", "110") for p in l["ports"]) and tgt.get("tls") != "seen":
                        tgt["plaintext"] = True
                # events: new link / health change
                if lk not in self.seen_links and self.prev_t:
                    self._new_link_event(nodes[l["source"]], tgt, l)
                self.seen_links[lk] = now
                old = self.link_health.get(lk)
                if old and l["health"] and old != l["health"] and l["health"] == "poor":
                    self.event("health", f"{nodes[l['source']]['label']} → {self._hname(tgt)} is struggling: {l['healthWhy']}", host=tgt["id"], proc=l["source"])
                if l["health"]:
                    self.link_health[lk] = l["health"]
            for lk, t in list(self.seen_links.items()):
                if lk not in links and now - t > 30:
                    del self.seen_links[lk]
                    self.link_health.pop(lk, None)
                    self.retr_win.pop(lk, None)
            # several different hosts with inflated round trips at once → the queue is on our side (Wi-Fi/router)
            rated = [l for l in links.values() if l.get("rtt") is not None]
            inflated = {l["target"] for l in rated if l.get("latencyIssue")}
            congested = len(inflated) >= 2 and len(inflated) >= 0.6 * len({l["target"] for l in rated})
            busiest = max(links.values(), key=lambda l: l["rateOut"] + l["rateIn"], default=None)
            wire = sum(i["txRate"] + i["rxRate"] for i in ifaces if i["kind"] != "virtual") or 1
            for l in links.values():
                if congested and l.get("latencyIssue") and l.get("health") in ("fair", "poor"):
                    up = max(links.values(), key=lambda x: x["rateOut"])
                    l["healthWhy"] = ("likely your own network link — most connections slowed at once"
                                      + (f", probably {nodes[up['source']]['label']}'s upload filling it" if up["rateOut"] > 50_000 else "") + ": " + l["healthWhy"])
                    l["localQueue"] = True
                elif l is busiest and l.get("latencyIssue") and (l["rateOut"] + l["rateIn"]) > 0.6 * wire:
                    l["healthWhy"] += " — likely this transfer filling your link (queueing)"
                    l["localQueue"] = True

            # ---- blocked attempts (firewall log) shown as hosts with a refused link
            blocked = MACHINE.recent_blocked(600) if not DEMO else DEMO.blocked()
            for b in blocked:
                hid = f"h:{b['ip']}"
                h = nodes.get(hid)
                if not h:
                    name, srcn, names = self.name_for(b["ip"])
                    h = nodes[hid] = {"id": hid, "type": "host", "label": b["ip"], "ip": b["ip"], "kind": ip_kind(b["ip"]),
                                      "ports": set(), "protos": set(), "sent": 0, "recv": 0, "rateOut": 0.0, "rateIn": 0.0,
                                      "cc": geo.DB.lookup(b["ip"]), "dns": name, "nameSource": srcn, "names": names,
                                      "refusedOnly": True}
                    enrich_host(h)
                h["refused"] = h.get("refused", 0) + 1
                h["lastRefused"] = max(h.get("lastRefused", 0), b["t"])
                h["firstRefused"] = min(h.get("firstRefused", b["t"]), b["t"])
                if b.get("uid") is not None:
                    h["refusedUid"] = b["uid"]
                h.setdefault("refusedBy", b["rule"])
                if b.get("port"):
                    h["ports"].add(b["port"])
                if b.get("proto"):
                    h["protos"].add(b["proto"])
                if b.get("user"):
                    h.setdefault("refusedUsers", set()).add(b["user"])
                if b.get("app"):
                    h.setdefault("refusedApps", set()).add(b["app"])

            self.prev, self.prev_t = cur, now
            PROCS.prune({k[1] for k in cur})

            # ---- our own traffic (observer effect), measured at the server
            with self.self_lock:
                st, self.self_traffic = self.self_traffic, {}
            observer = None
            if st and dt:
                observer = {"clients": [{"label": k, "rateOut": v[0] / dt, "rateIn": v[1] / dt, "requests": v[2]}
                                        for k, v in st.items()],
                            "interval": self.interval, "pid": MY_PID}

            # ---- control state
            ctr = CONTROL.counters()
            blocks = []
            for b in CONTROL.blocks.values():
                b = dict(b)
                key = "hosts4" if b["kind"] == "host" and ":" not in b.get("ip", ":") else "hosts6" if b["kind"] == "host" else b["id"]
                b["refusedPackets"] = ctr.get(key) if b["kind"] == "app" else None
                blocks.append(b)
                if b["kind"] == "host" and f"h:{b['ip']}" in nodes:
                    nodes[f"h:{b['ip']}"]["blockedHere"] = True
                if b["kind"] == "app":
                    b.pop("rules", None)
                    for n in nodes.values():
                        if n["type"] == "process" and app_key(n) == b["app"]:
                            n["blockedHere"] = True

            if CONTROL.blocks and not DEMO:
                seen = {}
                for n in nodes.values():
                    if n["type"] == "process":
                        n["app"] = next((unit_app(u) for u in n["units"] if unit_app(u)), None)
                        for pid in n["pids"]:
                            cg = PROCS.get(pid).get("cgroup")
                            if cg:
                                seen.setdefault(app_key(n), set()).add(cg)
                CONTROL.enforce(seen)
            if not self.prev_t or not self.preexisting and self.seq == 0:
                self.preexisting = set(nodes)
            for lk_, l in links.items():
                a_ = self.acc.get(f"{lk_[0]}→{lk_[1]}", [0, 0]); l["accOut"], l["accIn"] = a_
            for n in nodes.values():
                a_ = self.acc.get(n["id"], [0, 0]); n["accOut"], n["accIn"] = a_
                if n["id"] in self.preexisting:
                    n["preexisting"] = True
                for k in ("pids", "users", "units", "protos", "refusedUsers", "refusedApps"):
                    if k in n:
                        n[k] = sorted(n[k])
                if "ports" in n:
                    n["ports"] = sorted(n["ports"], key=lambda p: int(p) if p.isdigit() else 0)
                if n["type"] == "process":
                    n["app"] = next((unit_app(u) for u in n["units"] if unit_app(u)), None)
                    n["icon"] = bool(icons.icon_for(n["label"], n["app"]))
                fs = self.first_seen.setdefault(n["id"], n.get("firstRefused") or now)
                if n.get("firstRefused") and n["firstRefused"] < fs:
                    fs = self.first_seen[n["id"]] = n["firstRefused"]
                n["firstSeen"] = fs
                n["isNew"] = fs - self.started > 3 * self.interval and now - fs < 600
            pol = self.policy_snapshot()
            SAMPLER_NODES.clear(); SAMPLER_NODES.update(nodes)
            for n in nodes.values():
                n["verdict"] = verdict(n, pol, links.values())

            # ---- totals, coverage (how much of the interface traffic we can attribute)
            out_rate = sum(l["rateOut"] for l in links.values() if nodes[l["target"]]["type"] == "host" and nodes[l["target"]]["kind"] != "loopback")
            in_rate = sum(l["rateIn"] for l in links.values() if nodes[l["target"]]["type"] == "host" and nodes[l["target"]]["kind"] != "loopback")
            if_out = sum(i["txRate"] for i in ifaces if i["kind"] != "virtual")
            if_in = sum(i["rxRate"] for i in ifaces if i["kind"] != "virtual")
            self.history.append([round(now, 1), round(out_rate), round(in_rate), round(if_out), round(if_in)])
            win = list(self.history)[-15:]
            seen_b, wire_b = sum(h[1] + h[2] for h in win), sum(h[3] + h[4] for h in win)
            self.coverage = min(1.0, seen_b * 1.05 / wire_b) if wire_b > 2048 * len(win) else None   # +5% ≈ packet headers

            t_end = time.perf_counter()
            self.timing.append(((t_ss - t_start) * 1000, (t_end - t_start) * 1000))
            self.seq += 1
            snap = {
                "version": VERSION, "seq": self.seq, "time": now, "interval": dt, "pollEvery": self.interval,
                "root": IS_ROOT or bool(DEMO), "sniff": bool(SNIFFER and SNIFFER.running), "demo": bool(DEMO),
                "host": socket.gethostname(),
                "nodes": list(nodes.values()), "links": list(links.values()),
                "ifaces": ifaces, "dns": dns_servers() if not DEMO else DEMO.dns(),
                "totals": {"out": out_rate, "in": in_rate, "ifOut": if_out, "ifIn": if_in,
                           "coverage": self.coverage, "linkCongested": congested},
                "history": list(self.history),
                "events": list(self.events)[-40:],
                "observer": observer,
                "policy": pol, "started": self.started, "healthRules": HEALTH_RULES, "healthTable": HEALTH_TABLE,
                "control": {"available": CONTROL.available, "blocks": blocks, "error": CONTROL.error},
                "coverageNotes": self.coverage_notes(),
                "coverageCauses": self.coverage_causes(sum(1 for x in socks if x["proto"] == "udp")),
                "perf": {"sampleMs": round((t_end - t_start) * 1000, 1), "ssMs": round((t_ss - t_start) * 1000, 1),
                         "sockets": len(socks)},
            }
            self.snapshot = snap
            self._snap_json = None
            return snap

    def snapshot_json(self) -> bytes:
        with self.lock:
            if self._snap_json is None:
                self._snap_json = json.dumps(self.snapshot, separators=(",", ":")).encode()
            return self._snap_json

    def policy_snapshot(self):
        if DEMO:
            return DEMO.policy()
        if not MACHINE.present:
            return {"provider": None}
        g = MACHINE.grants()
        st = MACHINE.state or {}
        return {"provider": "machine", "lockdown": MACHINE.lockdown(),
                "grants": [{"name": k, "domains": v.get("domains", []), "reason": v.get("reason"),
                            "kind": v.get("kind"), "since": v.get("since"), "until": v.get("expires") or v.get("until")} for k, v in g.items()],
                "modes": list((st.get("modes") or {}).keys()),
                "dropLog": IS_ROOT, "resolverLog": IS_ROOT}

    def coverage_notes(self):
        root = IS_ROOT or bool(DEMO)
        sniff = bool(SNIFFER and SNIFFER.running) or bool(DEMO)
        n = [
            {"what": "Bytes per TCP connection", "status": "exact",
             "how": f"The kernel's own counters, read every {self.interval:g} s. Totals and map sizes count what moved since monitoring started and never go down; each connection's lifetime count is shown separately in its details."},
            {"what": "UDP and QUIC (HTTP/3, calls)", "status": "partial",
             "how": "Connected UDP sockets are shown, without sizes or health (Linux keeps no per-socket UDP byte counts). Unconnected UDP — DNS, local discovery, some calls — isn't shown at all."},
            {"what": "Which processes are visible", "status": "exact" if root else "partial",
             "how": "All users and system services (admin mode)." if root else "Only your own processes. Turn on admin mode to include system services and other users."},
            {"what": "Host names", "status": "inferred",
             "how": ("Matched from DNS answers and the server name apps send when opening TLS, seen on the wire. " if sniff else
                     "From the local resolver's log. " if IS_ROOT and MACHINE.present else "From reverse DNS only, which is often missing or generic. ")
                    + "One address can serve many names (CDNs), so the name shown is the most recent one used for it."},
            {"what": "Network owner and country", "status": "inferred",
             "how": "From DB-IP's offline databases (who the address block is registered to, and where). Shared content networks (CDNs) serve from many places, so the country can be wrong."},
            {"what": "Connection health", "status": "derived", "how": HEALTH_RULES},
            {"what": "Units", "status": "exact", "how": "Decimal, as on macOS: 1 KB = 1,000 bytes, 1 MB = 1,000,000 bytes."},
            {"what": f"Connections shorter than {self.interval:g} s", "status": "partial",
             "how": "Can be missed between samples. The interface total still counts their bytes — that's part of the gap in “Accounted for”."},
        ]
        if MACHINE.present or DEMO:
            n.append({"what": "Refused connections", "status": "exact" if root else "missing",
                      "how": "From the firewall's kernel log (rate-limited under bursts), with time, address, port and user. The app is named when its socket is still visible; otherwise it's unknown." if root
                      else "Reading the firewall log needs admin mode."})
        n.append({"what": "Encryption", "status": "inferred",
                  "how": "“TLS seen” when the encrypted handshake was observed (admin mode); otherwise judged from the port, e.g. 443 is usually HTTPS and 80 usually unencrypted."})
        return n

    def coverage_causes(self, socks_udp):
        c = []
        if socks_udp:
            c.append(f"{plural(socks_udp, 'UDP/QUIC connection')} (no byte counts)")
        if not (IS_ROOT or DEMO):
            c.append("other users' and system processes")
        c.append("closed or unconnected sockets")
        c.append(f"connections under {self.interval:g} s")
        return c

    def _hname(self, h):
        return h.get("dns") or h.get("label")

    @staticmethod
    def _pct(x):
        return "n/a" if x is None else f"{x:.1%}"

    def _new_link_event(self, p, h, l):
        if p.get("type") != "process":
            return
        where = self._hname(h)
        extra = []
        if h.get("service"):
            extra.append(h["service"])
        if h.get("cc") and h["cc"] != "LAN":
            extra.append(h["cc"])
        if h.get("plaintext"):
            extra.append("unencrypted")
        self.event("new", f"{p['label']} connected to {where}" + (f" ({', '.join(extra)})" if extra else ""),
                   proc=p["id"], host=h["id"])


SAMPLER = Sampler()


def advice_for(n):
    svc = (n.get("service") or "").lower()
    for k, v in ADVICE.items():
        if k in svc:
            return v
    return None


def who_text(n):
    users = n.get("refusedUsers") or []
    if not users:
        return "Something on this computer"
    u = users[0]
    return "Something running under your account" + (f" (“{u}”)" if u else "") if u == os.environ.get("SUDO_USER", u) or u == "user" \
        else f"Something running as “{u}”"


def verdict(n, pol, links):
    """identity: one neutral sentence on what it is; status: rows answering "is it expected?" and "is it working?"."""
    lockdown = bool(pol and pol.get("lockdown"))
    st = []
    if n["type"] == "process":
        if n.get("self") or n["id"] == "fw":
            return None
        mine = [l for l in links if l["source"] == n["id"]]
        hosts = [SAMPLER_NODES.get(l["target"]) for l in mine]
        hosts = [h for h in hosts if h and h["type"] == "host"]
        unknown = [h for h in hosts if h["kind"] == "internet" and not h.get("grant") and lockdown]
        bad = [l for l in mine if l.get("health") == "poor"]
        identity = (n.get("desc") or n["label"]) + f" — {plural(len(hosts), 'host')}" + (f", {plural(len(mine) - len(hosts), 'local app')}" if len(mine) > len(hosts) else "")
        if n.get("blockedHere"):
            st.append({"tone": "refused", "text": "Blocked by you — no network access, even after it restarts, until you unblock it."})
        elif unknown:
            st.append({"tone": "notice", "head": "Still open from before:", "text": f"{plural(len(unknown), 'host')} not in your current rules; a new connection to it would be blocked."})
        elif lockdown and hosts:
            st.append({"tone": "ok", "head": "Expected.", "text": "Every host it uses is allowed by your firewall rules."})
        if bad:
            w = bad[0]["healthWhy"]
            st.append({"tone": "poor", "head": "Struggling — " + ("losing packets." if "resent" in w else "high delay."), "text": w[0].upper() + w[1:] + "."})
        if not st:
            st.append({"tone": "ok", "head": "Running normally.", "text": ""})
        return {"identity": identity, "status": st}

    name = n.get("dns") or n["ip"]
    svc = f"{n['org']} — {n['service']}" if n.get("service") else n.get("netOrg") or "Unknown owner"
    where = "on your local network" if n["kind"] == "lan" else \
        ("served from a shared content network" if n.get("hosting") == "cdn" else "hosted in a public cloud" if n.get("hosting") == "cloud" else "")
    identity = svc + (f", {where}" if where else "") + "."
    if not n.get("dns") and n["kind"] == "internet":
        identity += " Service unknown — no name was seen" + ("" if IS_ROOT or DEMO else " (names need admin mode)") + "."
    if n.get("blockedHere"):
        st.append({"tone": "refused", "text": f"Blocked by you — new connections to {n['ip']} are refused until you unblock it or quit."})
    elif n.get("refusedOnly"):
        app = ", ".join(n["refusedApps"]) if n.get("refusedApps") else None
        st.append({"tone": "refused", "head": f"Blocked · at least {plural(n['refused'], 'attempt')} in 10 min.",
                   "text": "No connection was made. "
                           + (f"{app} tried." if app else f"{who_text(n)} tried; the firewall log can't say which app.")})
        adv = advice_for(n)
        if adv:
            st.append({"tone": "notice", "text": adv})
    elif n["kind"] == "lan":
        st.append({"tone": "ok", "text": "Local — this traffic stays on your network."})
    elif n.get("grant") and n["grant"]["grant"] == "open":
        st.append({"tone": "notice", "text": "Allowed because the firewall is temporarily open to everything."})
    elif n.get("grant"):
        g = n["grant"]
        st.append({"tone": "ok", "head": f"Allowed by your rule “{g['grant']}”.", "text": (g.get("reason") or "") })
    elif lockdown and n["kind"] == "internet" and n.get("ruleChecked"):
        st.append({"tone": "notice", "head": "Still open from before.", "text": "It started while it was allowed; the firewall doesn't cut open connections. "
                                           "It isn't in your current rules, so a new connection would be blocked."})
    elif lockdown and n["kind"] == "internet":
        st.append({"tone": "notice", "text": "No rule names this host. Turn on admin mode to check which rule let it through."})
    if n.get("plaintext"):
        st.append({"tone": "warn", "head": "Not encrypted (http).", "text": "Others on the network path could read this traffic."})
    if n.get("stalled"):
        st.append({"tone": "poor", "text": "Not answering — connection attempts are being retried."})
    elif n.get("health") in ("fair", "poor"):
        l = next((l for l in links if l["target"] == n["id"] and l.get("health") == n["health"]), {})
        why = l.get("healthWhy", "")
        lead = "Losing packets" if "resent" in why and not l.get("latencyIssue") else "Some delay" if n["health"] == "fair" else "High delay"
        st.append({"tone": n["health"], "head": f"{'Struggling' if n['health'] == 'poor' else 'Slow'} — {lead.lower()}.", "text": f"{why[0].upper() + why[1:]}." + (" Nothing to do unless the app stops working." if n["health"] == "fair" else "")})
    return {"identity": identity, "status": st}


SAMPLER_NODES: dict = {}


# ---------------------------------------------------------------- explain
def _clock(t):
    """Time token; the page formats it in the viewer's locale, the CLI with strftime."""
    return "{t:%d}" % t


def untoken(text):
    return re.sub(r"\{t:(\d+)\}", lambda m: time.strftime("%H:%M:%S", time.localtime(int(m.group(1)))), text)


def explain(target: str, snap=None):
    """Structured, sourced explanation of a host (id, IP or name) or process (id or name).
    Each fact: section, label, text, source, kind (exact | derived | inferred)."""
    snap = snap or SAMPLER.snapshot
    nodes = {n["id"]: n for n in snap["nodes"]}
    t = target.strip()
    n = nodes.get(t) or nodes.get(f"h:{t}") or nodes.get(f"p:{t}")
    if not n:
        n = next((x for x in snap["nodes"] if x["type"] == "host" and t.lower() in (x.get("names") or []) + [x.get("dns") or ""]), None)
    if not n:
        n = next((x for x in snap["nodes"] if t.lower() in (x.get("dns") or x["label"]).lower()), None)
    if not n:
        return {"error": f"nothing called {target!r} is connected right now"}
    links = [l for l in snap["links"] if n["id"] in (l["source"], l["target"])]
    facts = []
    lockdown = (snap.get("policy") or {}).get("lockdown")

    def fact(section, label, text, source, kind="exact"):
        facts.append({"section": section, "label": label, "text": text, "source": source, "kind": kind})

    if n["type"] == "host":
        if n.get("dns"):
            src = {"dns": "a DNS answer seen on the wire", "sni": "the server name the app sent when opening TLS",
                   "resolver": "the local resolver's log", "ptr": "reverse DNS (set by the address owner; may be generic)"}.get(n.get("nameSource"), "unknown")
            fact("what", "Name", n["dns"], src, "inferred")
            others = [x for x in (n.get("names") or []) if x != n["dns"]]
            if others:
                fact("what", "Also used for", ", ".join(others[:5]), "other names seen for the same address", "inferred")
        elif n["kind"] == "internet":
            fact("what", "Name", "none seen while monitoring", "names come from DNS answers and TLS server names seen while monitoring"
                 + ("" if IS_ROOT or DEMO else " (admin mode only)") + "; this address was probably looked up earlier or over encrypted DNS", "partial")
        if n.get("service"):
            fact("what", "Service", f"{n['org']} — {n['service']}", "built-in catalog, matched on the name", "inferred")
        if n.get("netOrg"):
            kind_word = {"cdn": " · shared content network (CDN)", "cloud": " · public cloud (could be any customer)"}.get(n.get("hosting"), "")
            fact("what", "Network owner", f"{n['netOrg']} (AS{n['asn']}){kind_word}", "DB-IP address-ownership data, offline", "inferred")
        ports = n.get("ports") or []
        if n.get("refusedOnly"):
            pass
        elif n.get("tls") == "seen":
            fact("what", "Encryption", "yes — TLS handshake seen", "packet capture", "exact")
        else:
            enc = [port_info(p) for p in ports]
            if any(e and e[1] is False for e in enc):
                fact("what", "Encryption", "probably none — port " + ", ".join(p for p, e in zip(ports, enc) if e and e[1] is False), "well-known port numbers", "inferred")
            elif any(e and e[1] for e in enc):
                fact("what", "Encryption", "probably yes — " + ", ".join(f"{e[0]} (port {p})" for p, e in zip(ports, enc) if e and e[1]), "well-known port numbers", "inferred")
        fact("where", "Address", f"{n['ip']} ({'IPv6' if ':' in n['ip'] else 'IPv4'}) · " + "/".join(x.upper() for x in n.get("protos") or []) + " port " + ", ".join(ports),
             "kernel connection table", "exact")
        if n["kind"] == "lan":
            fact("where", "Located", "on your local network", "private address range", "exact")
        elif n.get("cc"):
            fact("where", "Registered in", n["cc"] + (" — content networks and clouds serve from many places" if n.get("hosting") else ""), "DB-IP country data, offline", "inferred")
        for l in links:
            p = nodes.get(l["source"], {})
            if l.get("refused") or p.get("type") != "process":
                continue
            fact("who", "App", f"{p.get('label')} — " + plural(l["conns"], "connection") + (f", {l['connecting']} still connecting" if l.get("connecting") else ""),
                 "socket owner, from the kernel", "exact")
        # ---- firewall decision
        if n.get("refused"):
            fact("decision", "Result", "Blocked — no connection was made", "kernel firewall log", "exact")
            fact("decision", "What left", "probably only the DNS lookup for the name (unless the app uses encrypted DNS)", "how lookups work under this firewall", "inferred")
            fact("decision", "By", "your default block-everything rule" + (f" ({n.get('refusedBy')})" if n.get("refusedBy") else ""), "kernel firewall log", "exact")
            fact("decision", "Attempts", f"at least {n['refused']} in the last 10 min · first {_clock(n['firstRefused'])}, last {_clock(n['lastRefused'])}",
                 "kernel firewall log (rate-limited: bursts may be undercounted)", "exact")
            if n.get("refusedApps"):
                fact("who", "App", ", ".join(n["refusedApps"]), "matched by source port to a socket still trying to connect", "derived")
            else:
                fact("who", "App", "unknown — the firewall log records only the user account", "kernel firewall log", "exact")
            fact("who", "Account", ", ".join(n.get("refusedUsers") or ["unknown"]), "kernel firewall log", "exact")
        elif n.get("grant") and n["grant"].get("via") == "set":
            g = n["grant"]
            fact("decision", "Result", "Allowed", "firewall", "exact")
            fact("decision", "By rule", f"“{g['grant']}”" + (f" — {g['reason']}" if g.get("reason") else ""), "the firewall's live allowed-address lists", "exact")
            fact("decision", "Why this address", f"added to the rule's list when one of its names ({g['domain']}) was looked up"
                 + (f"; expires in {round(g['expires'] / 60)} min unless looked up again" if g.get("expires") else ""), "the firewall's live allowed-address lists", "exact")
            others = [x for x in (n.get("names") or []) if x != n.get("dns")]
            if n.get("hosting") or others:
                fact("decision", "Note", "rules work by address, so this allows everything served from this address"
                     + (f" — it also served {', '.join(others[:3])}" if others else f" ({'a shared CDN' if n.get('hosting') == 'cdn' else 'a shared cloud'})"),
                     "the firewall's design", "exact")
        elif n.get("grant"):
            g = n["grant"]
            fact("decision", "Result", "Allowed", "firewall rules", "exact")
            fact("decision", "By rule", f"“{g['grant']}” (covers {g['domain']})" + (f" — {g['reason']}" if g.get("reason") else ""), "firewall rules, matched on the name", "inferred")
        elif lockdown and n["kind"] == "internet":
            if n.get("ruleChecked"):
                fact("decision", "Result", "Still open from before — the firewall doesn't cut open connections", "deduced: the address is in no allowed list, and the firewall accepts established connections first", "derived")
                fact("decision", "Why", "this address is in no rule's list now, so the connection was opened while it was allowed — before lockdown, "
                     "or while an allowed name pointed here (list entries expire) — and the firewall keeps open connections running",
                     "the firewall's rule order: established connections are accepted first", "derived")
            else:
                fact("decision", "Result", "Allowed — which rule can't be checked without admin mode", "the firewall's lists are root-only", "exact")
        if n.get("blockedHere"):
            fact("decision", "Blocked by you", "new connections to this address are refused until you unblock it or quit", "this app's firewall table", "exact")
        # ---- health
        for l in links:
            if l.get("refused"):
                continue
            src = nodes[l["source"]]["label"]
            if l.get("health"):
                kindw = "receive-side " if l.get("rttKind") == "receive" else ""
                fact("health", src, f"{l['health']} — {l['healthWhy']}", "kernel TCP statistics", "derived")
                fact("health", "Round trip", f"{l['rtt']} ms {kindw}now · {l.get('minRtt')} ms at best", "kernel TCP statistics", "exact")
                fact("health", "Uploads resent", f"{l['retr']:.1%} ({'last 10 s' if l['retrBasis'] == 'now' else 'earlier in the connection; not rated'})"
                     if l.get("retr") is not None else "too little uploaded to judge", "kernel TCP statistics — only this computer's resends are visible", "exact")
            else:
                fact("health", src, "not rated — " + (l.get("healthWhy") or "not measured"), "kernel TCP statistics", "derived")
        # ---- amount
        if not n.get("refusedOnly"):
            if set(n.get("protos") or []) == {"udp"}:
                fact("amount", "Data", "not measured — Linux keeps no byte counts for UDP/QUIC", "kernel", "exact")
            else:
                fact("amount", "Lifetime of open connections", f"{fmt_bytes(n['recv'])} sent, {fmt_bytes(n['sent'])} received (includes time before monitoring)", "kernel TCP counters", "exact")
        fact("amount", "First seen", "already connected when monitoring started" if n.get("preexisting") else _clock(n["firstSeen"]), "this app's own record", "exact")
    else:
        fact("what", "Program", n.get("desc") or n["label"], "built-in catalog" if n.get("desc") else "process name", "inferred" if n.get("desc") else "exact")
        if n.get("app"):
            fact("who", "App", n["app"], "reported by the app's launcher (systemd scope name)", "inferred")
        fact("who", "Account", ", ".join(n.get("users") or ["?"]), "/proc/<pid>/status", "exact")
        for l in links:
            if l["source"] != n["id"]:
                continue
            h = nodes[l["target"]]
            what = h.get("dns") or (shortorg(h.get("netOrg")) + " · " + h.get("ip", "") if h.get("netOrg") else h["label"])
            rule = f"allowed by “{h['grant']['grant']}”" if h.get("grant") else ("blocked by you" if h.get("blockedHere") else "still open from before" if lockdown and h.get("kind") == "internet" else "")
            hw = {"good": "good", "fair": "slow", "poor": "struggling"}.get(l.get("health"))
            fact("where", "Talks to", what + (f" · {rule}" if rule else "") + (f" · {hw}" if hw else ""), "kernel connection table", "exact")
        fact("amount", "Lifetime of open connections", f"{fmt_bytes(n['sent'])} sent, {fmt_bytes(n['recv'])} received (includes time before monitoring)", "kernel TCP counters", "exact")
        fact("amount", "First seen", "already running when monitoring started" if n.get("preexisting") else _clock(n["firstSeen"]), "this app's own record", "exact")
        if n.get("exe"):
            fact("technical", "Executable", n["exe"], "/proc/<pid>/exe", "exact")
        if n.get("cmd"):
            fact("technical", "Command line", n["cmd"][:200], "/proc/<pid>/cmdline", "exact")
        if n.get("parent"):
            fact("technical", "Started by", n["parent"], "/proc parent process", "exact")
        fact("technical", "Process IDs", ", ".join(map(str, n["pids"])), "/proc", "exact")
        if n.get("units"):
            fact("technical", "systemd scope", ", ".join(n["units"]), "/proc/<pid>/cgroup", "exact")
    return {"id": n["id"], "type": n["type"], "title": n.get("dns") or n["label"], "verdict": n.get("verdict"),
            "facts": facts, "measuredAt": snap["time"]}


def shortorg(o):
    return re.sub(r",? (Inc|LLC|Ltd|PBC|Corporation|Corp|GmbH|B\.V|AG|S\.A)\.?$", "", o or "")


def fmt_bytes(b):
    """Decimal units, like macOS (1 KB = 1000 bytes)."""
    b = float(b or 0)
    for u in ("B", "KB", "MB", "GB"):
        if b < 1000 or u == "GB":
            return f"{b:.0f} {u}" if u == "B" else f"{b:.1f} {u}"
        b /= 1000


def report(snap) -> str:
    """Plain-text overview, written to be read by a person or by Claude."""
    nodes = {n["id"]: n for n in snap["nodes"]}
    L = []
    t = snap["totals"]
    L.append(f"Process Traffic {snap['version']} — {snap['host']} — {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snap['time']))}")
    L.append(f"View: {'all processes (root)' if snap['root'] else 'your processes only (not root)'}"
             + ("; DNS/SNI capture on" if snap["sniff"] else "") + ("; DEMO DATA" if snap["demo"] else ""))
    cov = t.get("coverage")
    L.append(f"Now: ↑ {fmt_bytes(t['out'])}/s ↓ {fmt_bytes(t['in'])}/s in visible connections; interfaces ↑ {fmt_bytes(t['ifOut'])}/s ↓ {fmt_bytes(t['ifIn'])}/s"
             + (f"; {cov:.0%} attributed" if cov is not None else ""))
    pol = snap.get("policy") or {}
    if pol.get("provider"):
        L.append(f"Firewall: {'lockdown ON' if pol.get('lockdown') else 'lockdown OFF'}; grants: " +
                 ", ".join(f"{g['name']} ({', '.join(g['domains'][:4])})" for g in pol.get("grants", [])))
    for i in snap["ifaces"]:
        w = f", Wi-Fi signal {i['wifi']['signal']:.0f} dBm" if i.get("wifi") else ""
        L.append(f"Interface {i['name']}{' (default via ' + str(i.get('gateway')) + ')' if i['default'] else ''}: "
                 f"↑ {fmt_bytes(i['txRate'])}/s ↓ {fmt_bytes(i['rxRate'])}/s, errors {i['rxErr'] + i['txErr']}, drops {i['rxDrop'] + i['txDrop']}{w}")
    L.append("")
    procs = sorted((n for n in snap["nodes"] if n["type"] == "process"), key=lambda n: -(n["sent"] + n["recv"]))
    L.append("Connections (process → host: bytes sent/received, health):")
    for p in procs:
        L.append(f"  {p['label']} [pid {', '.join(map(str, p['pids']))}{'; ' + p['desc'] if p.get('desc') else ''}]")
        for l in sorted((l for l in snap["links"] if l["source"] == p["id"]), key=lambda l: -(l["sent"] + l["recv"])):
            h = nodes[l["target"]]
            name = h.get("dns") or h["label"]
            bits = [f"{'+'.join(l['protos'])}/{','.join(l['ports'])}", f"{fmt_bytes(l['sent'])}↑ {fmt_bytes(l['recv'])}↓"]
            if l.get("rtt") is not None:
                bits.append(f"rtt {l['rtt']} ms")
            if l.get("retr") is not None:
                bits.append(f"resent {l['retr']:.1%}")
            if l.get("health"):
                bits.append(l["health"])
            if l.get("connecting"):
                bits.append(f"{l['connecting']} still connecting")
            if h.get("grant"):
                bits.append(f"allowed by '{h['grant']['grant']}'")
            if h.get("cc"):
                bits.append(h["cc"])
            L.append(f"    → {name}{' (' + h['service'] + ')' if h.get('service') else ''}: " + "; ".join(bits))
    refused = [n for n in snap["nodes"] if n.get("refused")]
    if refused:
        L.append("")
        L.append("Refused by the firewall (last 10 min):")
        for h in sorted(refused, key=lambda h: -h["refused"]):
            L.append(f"  {h['refused']}× {h.get('dns') or h['ip']}:{','.join(h['ports'])} ({h.get('service') or 'unknown service'})"
                     + (f" user {', '.join(h['refusedUsers'])}" if h.get("refusedUsers") else ""))
    if snap["control"]["blocks"]:
        L.append("")
        L.append("Blocked from the app: " + ", ".join(b["label"] for b in snap["control"]["blocks"]))
    ev = snap.get("events") or []
    if ev:
        L.append("")
        L.append("Recent events:")
        for e in ev[-12:]:
            L.append(f"  {time.strftime('%H:%M:%S', time.localtime(e['t']))} {e['text']}" + (f"  [by {e['actor']}]" if e.get("actor") else ""))
    L.append("")
    L.append("Coverage: " + "; ".join(f"{c['what']}: {c['status']}" for c in snap["coverageNotes"]))
    return "\n".join(L)


# ---------------------------------------------------------------- HTTP
class Handler(SimpleHTTPRequestHandler):
    server_version = "ProcessTraffic/" + VERSION
    sys_version = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=HERE, **kw)

    def _send(self, body: bytes, ctype="application/json", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        ua = self.headers.get("User-Agent", "")
        label = "this app · window" if "ProcessTraffic" in ua else \
                "a browser tab" if "Mozilla" in ua else "a command-line client"
        SAMPLER.note_self(label, len(body) + 200, len(self.requestline) + 300)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj).encode(), code=code)

    def _authed(self, query):
        return not TOKEN or parse_qs(query).get("t", [""])[0] == TOKEN

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path.startswith("/api/"):
            if not self._authed(query):
                return self._json({"error": "forbidden"}, 403)
            q = parse_qs(query)
            if path == "/api/flows":
                return self._send(SAMPLER.snapshot_json())
            if path == "/api/explain":
                return self._json(explain(q.get("id", [""])[0]))
            if path == "/api/report":
                return self._send(report(SAMPLER.snapshot).encode(), "text/plain; charset=utf-8")
            if path == "/api/icon":
                name = q.get("p", [""])[0]
                node = (SAMPLER.snapshot or {}).get("nodes", [])
                node = next((x for x in node if x["id"] == f"p:{name}"), None)
                ipath = icons.icon_for(name, node.get("app") if node else None) if node else None
                if not ipath:
                    return self._json({"error": "no icon"}, 404)
                with open(ipath, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml" if ipath.endswith(".svg") else "image/png")
                self.send_header("Cache-Control", "max-age=3600")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if path == "/api/quit":
                self._json({"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            return self._json({"error": "not found"}, 404)
        if path not in STATIC:
            return self.send_error(404)
        self.path = "/" + STATIC[path]
        super().do_GET()

    def do_POST(self):
        path, _, query = self.path.partition("?")
        if path != "/api/action" or not self._authed(query):
            return self._json({"error": "forbidden"}, 403)
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self._json({"error": "json only"}, 415)
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 65536)) or b"{}")
            return self._json(do_action(body))
        except Exception as e:
            return self._json({"error": str(e)}, 400)

    def end_headers(self):
        if not self.path.startswith("/api/"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'")
        super().end_headers()

    def log_message(self, *a):
        pass


NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def protected(n):
    """Targets that carry the Claude connection itself (base grant 'claude' / Claude's own app scope)."""
    if n.get("type") == "host":
        g = n.get("grant") or {}
        return g.get("grant") == "claude" or n.get("org") == "Anthropic"
    return n.get("label") in ("claude", "claude-desktop") or "anthropic" in (n.get("app") or "").lower()


def app_key(n):
    return n.get("app") or n.get("exe") or n["label"]


def do_action(a):
    SAMPLER.actor = (str(a.get("actor"))[:40] or None) if a.get("actor") else None
    try:
        return _do_action(a)
    finally:
        SAMPLER.actor = None


def _do_action(a):
    op = a.get("op")
    if not CONTROL.available:
        raise RuntimeError("controls need admin mode (root)")
    snap = SAMPLER.snapshot
    nodes = {n["id"]: n for n in snap["nodes"]}
    tgt = nodes.get(a.get("id"))
    if op in ("cut", "block-host", "block-app") and tgt and protected(tgt) and not a.get("force"):
        return {"needsConfirm": True,
                "error": "This carries the connection to Claude (Claude Code, the desktop app and Remote Control). "
                         "Cutting or blocking it can disconnect this session."}
    if op == "cut":
        n = nodes.get(a.get("id"))
        if not n:
            raise RuntimeError("not connected any more")
        if n["type"] == "host":
            r = {"cut": CONTROL.kill({"ip": n["ip"]})}
        else:
            r = {"cut": CONTROL.kill({"pid": True, "pids": set(n["pids"])})}
        SAMPLER.event("control", f"Disconnected {n.get('dns') or n['label']} ({plural(r['cut'], 'connection')} closed)", **({"host": n["id"]} if n["type"] == "host" else {"proc": n["id"]}))
        return r
    if op == "block-host":
        n = nodes.get(a.get("id")) or {}
        ip = n.get("ip") or a.get("ip")
        r = CONTROL.block_host(ip, n.get("dns") or ip)
        SAMPLER.event("control", f"Blocked {n.get('dns') or ip} ({plural(r['cut'], 'connection')} closed)", host=f"h:{ip}")
        return r
    if op == "block-app":
        n = nodes.get(a.get("id"))
        if not n or n["type"] != "process":
            raise RuntimeError("not a process")
        r = CONTROL.block_app(n["pids"][0], n.get("app") or n["label"], app_key(n))
        SAMPLER.event("control", f"Blocked app {n.get('app') or n['label']} ({plural(r['cut'], 'connection')} closed)", proc=n["id"])
        return r
    if op == "unblock":
        r = CONTROL.unblock(a.get("block", ""))
        SAMPLER.event("control", f"Unblocked {a.get('block', '').split(':', 1)[-1]}")
        return r
    if op == "machine-allow":
        name, reason = a.get("name", ""), a.get("reason", "").strip()
        domains = a.get("domains") or [a.get("domain", "")]
        domains = [d.lower().strip().rstrip(".") for d in domains if d and d.strip()]
        dur = a.get("for", "1h")
        if not NAME_RE.match(name) or not domains or not all(DOMAIN_RE.match(d) for d in domains) or not reason \
                or not re.match(r"^\d+[mhd]$", dur) or name in ("claude", "updates"):
            raise RuntimeError("need a short rule name, one or more names like example.com, a reason and a duration like 30m/2h")
        r = CONTROL.machine(["allow", name, *domains, "--reason", reason[:300], "--for", dur])
        SAMPLER.event("control", f"Rule “{name}”: allowed {', '.join(domains)} for {dur} — {reason}" if r["ok"] else f"Allowing {', '.join(domains)} failed")
        return r
    if op == "machine-extend":
        name, minutes = a.get("name", ""), int(a.get("minutes", 60))
        pol = SAMPLER.policy_snapshot()
        g = next((x for x in pol.get("grants", []) if x["name"] == name), None)
        if not g or not g.get("until") or g.get("kind") not in ("ad-hoc", "allow"):
            raise RuntimeError("only time-limited rules made with Allow can be extended")
        import datetime as _dt
        left = (_dt.datetime.fromisoformat(g["until"]) - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
        total = max(1, int((max(0, left) + minutes * 60) // 60))
        if DEMO:
            g["until"] = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=total)).isoformat()
            r = {"ok": True}
        else:
            r = CONTROL.machine(["allow", name, *g["domains"], "--reason", g.get("reason") or "extended", "--for", f"{total}m"])
        SAMPLER.event("control", f"Extended rule “{name}” by {minutes} min" if r["ok"] else f"Extending “{name}” failed")
        return r
    if op == "machine-revoke":
        name = a.get("name", "")
        if not NAME_RE.match(name) or name == "claude":
            raise RuntimeError("can't revoke that grant from here")
        r = CONTROL.machine(["revoke", name])
        SAMPLER.event("control", f"Revoked grant {name}" if r["ok"] else f"Revoke {name} failed")
        return r
    raise RuntimeError(f"unknown action {op!r}")


def runtime_path(root=IS_ROOT):
    """Where a running collector advertises its port and token to `ptctl` (mode 0600, removed on exit)."""
    uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or os.getuid())
    base = f"/run/user/{uid}" if os.path.isdir(f"/run/user/{uid}") else os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return os.path.join(base, "process-traffic-admin.json" if root else "process-traffic.json"), uid


def write_runtime(port):
    path, uid = runtime_path()
    try:
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"port": port, "token": TOKEN, "pid": os.getpid(), "root": IS_ROOT, "demo": bool(DEMO),
                       "version": VERSION, "started": time.time()}, f)
        if IS_ROOT:
            os.chown(path + ".tmp", uid, -1)
        os.replace(path + ".tmp", path)

        def cleanup():
            try:
                with open(path) as f:
                    if json.load(f).get("pid") == os.getpid():
                        os.unlink(path)
            except (OSError, ValueError):
                pass
        atexit.register(cleanup)
    except OSError as e:
        print(f"(couldn't write {path}: {e})", file=sys.stderr)


def watch_parent(pid, srv):
    while True:
        time.sleep(1)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            srv.shutdown()
            return
        except PermissionError:
            pass


def setup(args):
    global SNIFFER, TOKEN, DEMO
    TOKEN = getattr(args, "token", None)
    if getattr(args, "demo", False):
        import demo
        DEMO = demo.Scenario(scale=getattr(args, "demo_scale", 1))
        for bid, kind, ip, label in demo.DEMO_BLOCKS:
            CONTROL.blocks[bid] = {"id": bid, "kind": kind, "ip": ip, "label": label, "since": DEMO.t0 - 900}
    SAMPLER.interval = args.interval
    if IS_ROOT and not DEMO:
        if not args.no_sniff:
            SNIFFER = dnssniff.Sniffer()
            if not SNIFFER.start():
                print(f"(DNS capture unavailable: {SNIFFER.error})", file=sys.stderr)
        MACHINE.start_journal()
        MACHINE.read_dns_log()


def main():
    global TOKEN
    ap = argparse.ArgumentParser(description="Process Traffic collector")
    ap.add_argument("--port", type=int, default=8765, help="0 = pick a free port")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", help="require ?t=TOKEN on /api requests")
    ap.add_argument("--parent-pid", type=int, help="exit when this process exits")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between samples")
    ap.add_argument("--no-sniff", action="store_true", help="don't capture DNS/SNI names even as root")
    ap.add_argument("--demo", action="store_true", help="serve a synthetic, clearly-labelled scenario")
    ap.add_argument("--demo-scale", type=int, default=1, help="multiply the demo scenario (benchmarks)")
    ap.add_argument("--once", action="store_true", help="print a report after two samples and exit")
    ap.add_argument("--json", action="store_true", help="with --once/--explain: print JSON")
    ap.add_argument("--explain", metavar="TARGET", help="explain a host (IP or name) or process and exit")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()
    setup(args)

    if args.once or args.explain:
        geo.DB.load(); geo.ASN.load()
        SAMPLER.sample()
        time.sleep(min(args.interval, 2.0))
        snap = SAMPLER.sample()
        if args.explain:
            r = explain(args.explain, snap)
            if args.json:
                print(json.dumps(r, indent=1))
            elif "error" in r:
                print(r["error"]); sys.exit(1)
            else:
                print(r["title"])
                for f in r["facts"]:
                    print(f"  [{f['section']}] {f.get('label', '')}: {untoken(f['text'])}   ← {f['source']} ({f['kind']})")
        else:
            print(json.dumps(snap, indent=1) if args.json else report(snap))
        return

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    SAMPLER.start()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    port = srv.server_address[1]
    SELF_PORTS.add(str(port))
    print(f"PORT {port}", flush=True)
    if not TOKEN:
        import secrets
        TOKEN = secrets.token_urlsafe(16)
    write_runtime(port)
    print(f"Process Traffic: http://{args.host}:{port}/" + (f"?t={TOKEN}" if TOKEN else ""), flush=True)
    if args.parent_pid:
        threading.Thread(target=watch_parent, args=(args.parent_pid, srv), daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        CONTROL.teardown()


if __name__ == "__main__":
    main()
