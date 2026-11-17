"""Run: python3 -m unittest discover -s tests"""
import argparse
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import collector as c  # noqa: E402
import dnssniff  # noqa: E402

SS_TCP = """ESTAB     0      0                 192.168.5.123:48550          160.79.104.10:443   users:(("claude",pid=143008,fd=26))         timer:(keepalive,20sec,0)
\t ts sack cubic wscale:13,7 rto:216 rtt:15.771/7.829 ato:40 mss:1448 cwnd:10 bytes_sent:13988 bytes_retrans:616 bytes_acked:13373 bytes_received:11924 segs_out:116 lastrcv:10904 minrtt:10.799 snd_wnd:131072
TIME-WAIT 0      0                     127.0.0.1:34041              127.0.0.1:58478                                             timer:(timewait,21sec,0)
SYN-SENT  0      1                 192.168.5.123:51000          104.16.3.35:443   users:(("node",pid=9901,fd=20))   timer:(on,2.1sec,2)
\t cubic rto:4000 mss:524 cwnd:1 bytes_sent:0 bytes_received:0
ESTAB     0      0      [::ffff:127.0.0.1]:45001 [::ffff:127.0.0.1]:45002 users:(("code",pid=9900,fd=3))
\t cubic rtt:0.05/0.01 bytes_sent:500 bytes_received:250
"""
SS_UDP = """0      0      192.168.5.123%wlx90de8042529b:68        192.168.5.1:67
0      0           [2605:a601:ab2c:2f01::8]:38516 [2607:6bc0::10]:443 users:(("claude-desktop",pid=126403,fd=33))
"""
DROP = ("1794066000.123456 debian kernel: machine-drop: IN= OUT=wlan0 SRC=192.168.5.123 DST=34.149.66.165 LEN=60 "
        "PROTO=TCP SPT=47590 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 UID=0 GID=0")


class Parsing(unittest.TestCase):
    def test_tcp(self):
        s = list(c.parse_ss(SS_TCP, "tcp"))
        self.assertEqual([x["proc"] for x in s], ["claude", "node", "code"])   # TIME-WAIT without owner skipped
        a = s[0]
        self.assertEqual((a["ph"], a["pp"], a["sent"], a["recv"], a["retrans"]), ("160.79.104.10", "443", 13988, 11924, 616))
        self.assertAlmostEqual(a["rtt"], 15.771)
        self.assertAlmostEqual(a["minrtt"], 10.799)
        self.assertEqual(s[1]["state"], "SYN-SENT")
        self.assertEqual(s[1]["synRetries"], 2)
        self.assertEqual(s[2]["lh"], "127.0.0.1")   # IPv4-mapped normalised

    def test_udp(self):
        s = list(c.parse_ss(SS_UDP, "udp"))
        self.assertEqual(len(s), 1)                  # DHCP socket without an owner is skipped
        self.assertEqual((s[0]["proc"], s[0]["ph"], s[0]["pp"], s[0]["proto"]), ("claude-desktop", "2607:6bc0::10", "443", "udp"))

    def test_drop(self):
        e = c.parse_drop(DROP)
        self.assertEqual((e["rule"], e["ip"], e["port"], e["proto"], e["user"]), ("machine-drop", "34.149.66.165", "443", "tcp", "root"))
        self.assertIsNone(c.parse_drop("1794066000.1 debian kernel: usb 1-1: new device"))

    def test_helpers(self):
        self.assertEqual(c.suffix_match("api.anthropic.com", ["anthropic.com"]), "anthropic.com")
        self.assertIsNone(c.suffix_match("notanthropic.com", ["anthropic.com"]))
        self.assertEqual(c.ip_kind("192.168.1.2"), "lan")
        self.assertEqual(c.ip_kind("::1"), "loopback")
        self.assertEqual(c.ip_kind("8.8.8.8"), "internet")
        self.assertEqual(c.unit_app("app-gnome-firefox-4120.scope"), "firefox")
        self.assertEqual(c.unit_app("app-com.anthropic.Claude-126293.scope"), "com.anthropic.Claude")

    def test_health(self):
        h = lambda *a: c.health_of(*a)[0]
        self.assertEqual(h(20, 15, 0.0), "good")
        self.assertEqual(h(180, 170, 0.0), "good")      # far away but steady: not penalised
        self.assertEqual(h(120, 30, 0.0), "fair")       # 4x its best and 90 ms above it: queueing
        self.assertEqual(h(350, 340, 0.0), "fair")      # slow on any path
        self.assertEqual(h(20, 15, 0.04), "fair")
        self.assertEqual(h(900, 850, 0.0), "poor")
        self.assertEqual(h(300, 50, 0.0), "poor")       # 6x and 250 ms above best
        self.assertEqual(h(20, 15, 0.08), "poor")
        self.assertEqual(h(20, 15, 0.025), "good")      # ordinary Wi-Fi resend levels
        self.assertIsNone(h(None, None, None))

    def test_sni(self):
        # minimal ClientHello with SNI "example.com"
        name = b"example.com"
        sni = b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") + (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
        exts = sni
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        self.assertEqual(dnssniff.parse_sni(rec), "example.com")


class DemoSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c.geo.DB.load(); c.geo.ASN.load()
        c.setup(argparse.Namespace(demo=True, demo_scale=1, interval=2.0, no_sniff=True, token="tok"))
        c.SAMPLER.sample()
        import time; time.sleep(0.3)
        for _ in range(3):   # health needs two consecutive bad samples before "poor" (hysteresis)
            time.sleep(0.2)
            cls.snap = c.SAMPLER.sample()

    def test_invariants(self):
        ids = {n["id"] for n in self.snap["nodes"]}
        for l in self.snap["links"]:
            self.assertIn(l["source"], ids); self.assertIn(l["target"], ids)
            self.assertGreaterEqual(l["rateOut"], 0); self.assertGreaterEqual(l["rateIn"], 0)
        t = self.snap["totals"]
        self.assertGreater(t["in"], 200_000)   # every socket's bytes are counted, whatever its health path
        cov = t["coverage"]
        self.assertTrue(cov is None or 0 <= cov <= 1)
        json.dumps(self.snap)   # serialisable (no sets left)

    def test_features_present(self):
        n = {x["id"]: x for x in self.snap["nodes"]}
        self.assertTrue(any(x.get("refused") for x in n.values()))
        self.assertTrue(any(l["connecting"] for l in self.snap["links"]))
        self.assertTrue(all(l["health"] is None for l in self.snap["links"] if l["connecting"] == l["conns"]))   # never rate a SYN
        self.assertTrue(all(n.get("verdict") for n in self.snap["nodes"] if n["type"] == "host"))
        self.assertTrue(n["h:93.184.215.14"].get("plaintext"))
        self.assertEqual(n["h:160.79.104.10"]["grant"]["grant"], "claude")

    def test_explain_and_report(self):
        e = c.explain("example.com", self.snap)
        secs = {f["section"] for f in e["facts"]}
        self.assertTrue({"what", "where", "who", "decision", "amount"} <= secs)
        self.assertIn("probably none", " ".join(f["text"] for f in e["facts"]))
        n = {x["id"]: x for x in self.snap["nodes"]}
        self.assertNotIn("grant", n["h:34.149.66.165"])   # refused Datadog on Google Cloud must not inherit a Google rule
        r = c.explain("h:34.149.66.165", self.snap)
        self.assertIn("Blocked", " ".join(f["text"] for f in r["facts"] if f["section"] == "decision"))
        self.assertIn("error", c.explain("nothing-like-this", self.snap))
        self.assertIn("Refused by the firewall", c.report(self.snap))

    def test_guard(self):
        r = c.do_action({"op": "block-host", "id": "h:160.79.104.10"})
        self.assertTrue(r.get("needsConfirm"))

    def test_http_token(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), c.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(base + "/api/flows")
            self.assertEqual(cm.exception.code, 403)
            with urllib.request.urlopen(base + "/api/flows?t=tok") as r:
                self.assertEqual(json.load(r)["demo"], True)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(base + "/collector.py")
            self.assertEqual(cm.exception.code, 404)
            req = urllib.request.Request(base + "/api/action?t=tok", data=b"{}", headers={"Content-Type": "text/plain"})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req)
            self.assertEqual(cm.exception.code, 415)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
