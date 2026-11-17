"""Synthetic scenario for `--demo`: a busy laptop, so every part of the UI has something to show
(healthy and degraded links, QUIC, a connection still trying, refused attempts, unencrypted HTTP).
The page shows a "Demo data" badge whenever this is on. `--demo-scale N` multiplies it for benchmarks."""
import math
import random
import time

APPS = [
    # name, pid, unit, user, [(ip, port, proto, name, kB/s out, kB/s in, rtt ms, retr share)]
    ("firefox", 4120, "app-gnome-firefox-4120.scope", "user", [
        ("140.82.112.4", "443", "tcp", "github.com", 2, 40, 31, 0.0),
        ("185.199.108.133", "443", "tcp", "raw.githubusercontent.com", 1, 220, 24, 0.0),
        ("142.250.72.110", "443", "udp", "www.youtube.com", 0, 0, None, None),
        ("91.198.174.192", "443", "tcp", "en.wikipedia.org", 0.5, 12, 142, 0.0),
        ("93.184.215.14", "80", "tcp", "example.com", 0.2, 3, 88, 0.0),
    ]),
    ("claude-desktop", 2210, "app-com.anthropic.Claude-2190.scope", "user", [
        ("160.79.104.10", "443", "tcp", "api.anthropic.com", 3, 9, 16, 0.0),
        ("2607:6bc0::10", "443", "udp", "claude.ai", 0, 0, None, None),
        ("142.250.191.78", "443", "tcp", None, 0.1, 0.4, 24, 0.0),
    ]),
    ("claude", 3301, "app-gnome-claude-3301.scope", "user", [
        ("160.79.104.10", "443", "tcp", "api.anthropic.com", 6, 14, 15, 0.0),
        ("34.36.57.103", "443", "tcp", "bridge.claudeusercontent.com", 0.4, 0.6, 22, 0.0),
    ]),
    ("spotify", 5501, "app-gnome-spotify-5501.scope", "user", [
        ("35.186.224.25", "443", "tcp", "spclient.wg.spotify.com", 0.3, 2, 48, 0.0),
        ("151.101.2.248", "443", "tcp", "audio-ak.spotifycdn.scdn.co", 0.5, 160, (92, 85), 0.0),
    ]),
    ("dropbox", 6810, "app-gnome-dropbox-6810.scope", "user", [
        ("162.125.21.3", "443", "tcp", "content.dropboxapi.com", 320, 4, (64, 41), 0.063),
    ]),
    ("slack", 6610, "app-gnome-slack-6610.scope", "user", [
        ("3.120.153.71", "443", "tcp", "wss-primary.slack.com", 0.2, 0.4, 168, 0.013),
    ]),
    ("apt", 7701, "apt-daily.service", "_apt", [
        ("151.101.130.132", "443", "tcp", "deb.debian.org", 0.4, 610, 19, 0.002),
    ]),
    ("ssh", 8801, "session-2.scope", "user", [
        ("192.168.5.20", "22", "tcp", "nas.local", 0.8, 1.2, 3, 0.0),
    ]),
    ("node", 9901, "app-gnome-code-9900.scope", "user", [
        ("104.16.3.35", "443", "tcp", "registry.npmjs.org", 0, 0, None, None),   # still connecting
    ]),
]
LOOPBACK = [("code", 9900, "node", 9901, "app-gnome-code-9900.scope", 3, 3)]
DEMO_BLOCKS = [("host:142.250.80.34", "host", "142.250.80.34", "stats.g.doubleclick.net")]
REFUSED = [("34.149.66.165", "443", "tcp", "http-intake.logs.us5.datadoghq.com", 6),
           ("3.33.252.61", "21116", "tcp", "rs-ny.rustdesk.com", 2)]
POLICY = {"provider": "machine", "lockdown": True, "dropLog": True, "resolverLog": True, "modes": [],
          "grants": [{"name": "claude", "domains": ["claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com", "clau.de"],
                      "reason": "Claude Desktop, Claude Code and Remote Control — the connection we work through",
                      "kind": "base", "since": "2026-11-07T13:31:56+00:00"},
                     {"name": "dev-web", "domains": ["github.com", "githubusercontent.com", "npmjs.org", "wikipedia.org", "example.com"],
                      "reason": "Research and package downloads for the networkgrafh project", "kind": "allow",
                      "since": "2026-11-07T15:02:10+00:00", "until": None},   # set to 40 min from start
                     {"name": "media", "domains": ["spotify.com", "scdn.co", "slack.com", "youtube.com"],
                      "reason": "Music and team chat while working", "kind": "mode", "since": "2026-11-07T15:10:00+00:00"},
                     {"name": "updates", "domains": ["deb.debian.org", "security.debian.org"],
                      "reason": "Boot-time security updates", "kind": "base", "since": "2026-11-07T13:32:00+00:00"}]}


class Scenario:
    def __init__(self, scale=1, seed=7):
        self.rng = random.Random(seed)
        self.t0 = time.time()
        self.scale = scale
        self.counters = {}
        self.names = {}
        self.procs = {}
        self.conns = []
        for k in range(scale):
            for name, pid, unit, user, peers in APPS:
                pid2 = pid + k * 100000
                self.procs[pid2] = {"pid": pid2, "user": user, "unit": unit, "cgroup": f"/user.slice/{unit}",
                                    "exe": f"/usr/bin/{name}", "cmd": f"/usr/bin/{name}", "parent": "systemd"}
                for j, (ip, port, proto, host, kout, kin, rtt, retr) in enumerate(peers):
                    if k:
                        ip = self._shift(ip, k)
                    if host:
                        self.names[ip] = host
                    nconn = 1 + (j % 3 == 0) + (name == "firefox")
                    for c in range(nconn):
                        self.conns.append(dict(proc=name, pid=pid2, ip=ip, port=port, proto=proto, kout=kout / nconn,
                                               kin=kin / nconn, rtt=rtt, retr=retr, lp=str(40000 + len(self.conns))))
        self.loop = LOOPBACK
        import datetime as _dt
        for g in POLICY["grants"]:
            if g["name"] == "dev-web" and not g["until"]:
                g["until"] = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=40)).isoformat()
        self.start_bytes = {i: (self.rng.randint(20_000, 4_000_000), self.rng.randint(80_000, 40_000_000)) for i in range(len(self.conns))}

    @staticmethod
    def _rtt(r):
        return r if isinstance(r, tuple) else (r, r * 0.8)

    @staticmethod
    def _shift(ip, k):
        if ":" in ip:
            return ip.rsplit(":", 1)[0] + f":{k:x}"
        a = ip.split(".")
        a[-1] = str((int(a[-1]) + k) % 250 + 1)
        return ".".join(a)

    def sockets(self):
        t = time.time() - self.t0
        out = []
        self._t = t
        for i, c in enumerate(self.conns):
            s0, r0 = self.start_bytes[i]
            # integral of a rate that wobbles between 0.4x and 1.6x — counters only ever go up, like the kernel's
            prog = t - 4.2 * math.cos(t / 7 + i) + 4.2 * math.cos(i)
            connecting = c["rtt"] is None and c["proto"] == "tcp"
            sent = 0 if connecting or c["proto"] == "udp" else int(s0 + c["kout"] * 1024 * prog)
            recv = 0 if connecting or c["proto"] == "udp" else int(r0 + c["kin"] * 1024 * prog)
            out.append({"proto": c["proto"], "state": "SYN-SENT" if connecting else "ESTAB", "proc": c["proc"], "pid": c["pid"],
                        "lh": "192.168.5.123" if ":" not in c["ip"] else "2605:a601::8", "lp": c["lp"], "ph": c["ip"], "pp": c["port"],
                        "sent": sent, "recv": recv, "retrans": int(sent * (c["retr"] or 0)),
                        "rtt": None if c["rtt"] is None else self._rtt(c["rtt"])[0] * (1 + 0.15 * math.sin(t / 3 + i)),
                        "rttvar": 2.0, "minrtt": None if c["rtt"] is None else self._rtt(c["rtt"])[1],
                        "synRetries": 2 if connecting else 0, "lastrcv": 120})
        for a, apid, b, bpid, unit, kout, kin in self.loop:
            self.procs.setdefault(apid, {"pid": apid, "user": "user", "unit": unit, "cgroup": f"/user.slice/{unit}",
                                         "exe": f"/usr/share/code/{a}", "cmd": a, "parent": "systemd"})
            v = int(5_000_000 + kout * 1024 * t)
            out.append({"proto": "tcp", "state": "ESTAB", "proc": a, "pid": apid, "lh": "127.0.0.1", "lp": "45001",
                        "ph": "127.0.0.1", "pp": "45002", "sent": v, "recv": v // 2, "retrans": 0, "rtt": 0.05,
                        "rttvar": 0.01, "minrtt": 0.02, "synRetries": 0, "lastrcv": 5})
            out.append({"proto": "tcp", "state": "ESTAB", "proc": b, "pid": bpid, "lh": "127.0.0.1", "lp": "45002",
                        "ph": "127.0.0.1", "pp": "45001", "sent": v // 2, "recv": v, "retrans": 0, "rtt": 0.05,
                        "rttvar": 0.01, "minrtt": 0.02, "synRetries": 0, "lastrcv": 5})
        tot_s = sum(x["sent"] for x in out if not x["ph"].startswith("127."))
        tot_r = sum(x["recv"] for x in out if not x["ph"].startswith("127."))
        # what the wire carried: the sockets, plus headers (~5%), plus QUIC video that has no per-socket counters
        self._wire = (tot_s * 1.05 + 9_000 * t, tot_r * 1.05 + 160_000 * t)
        return out

    def proc(self, pid):
        return self.procs.get(pid, {"pid": pid})

    def pids_in(self, cg):
        return {p for p, i in self.procs.items() if i.get("cgroup") == cg}

    def name(self, ip):
        return self.names.get(ip) or {r[0]: r[3] for r in REFUSED}.get(ip)

    def blocked(self):
        out = []
        for j, (ip, port, proto, _, n) in enumerate(REFUSED):
            for k in range(n):
                out.append({"t": self.t0 - 400 + 60 * k + 7 * j, "rule": "machine-drop", "ip": ip, "port": port, "proto": proto,
                            "user": "user", "uid": "1000", "syn": True})
        return out

    def ifaces(self):
        now = time.time()
        tx, rx = getattr(self, "_wire", (0, 0))
        prev = getattr(self, "_prev_wire", None)
        dt = now - prev[0] if prev else None
        rxr = (rx - prev[2]) / dt if dt else 0.0
        txr = (tx - prev[1]) / dt if dt else 0.0
        self._prev_wire = (now, tx, rx)
        return [{"name": "wlp2s0", "default": True, "kind": "wifi", "gateway": "192.168.5.1",
                 "rx": int(9e8 + rx), "tx": int(2e8 + tx), "rxPk": 2_400_000, "txPk": 900_000, "rxErr": 0, "txErr": 0, "rxDrop": 214, "txDrop": 0,
                 "rxRate": max(0.0, rxr), "txRate": max(0.0, txr), "wifi": {"quality": 58.0, "signal": -54.0}}]

    def dns(self):
        return ["127.0.0.1"]

    def rule_for_ip(self, ip):
        name = self.names.get(ip)
        for g in POLICY["grants"]:
            if name and any(name == d or name.endswith("." + d) for d in g["domains"]):
                return g["name"], 30000
        return None

    def policy(self):
        return POLICY
