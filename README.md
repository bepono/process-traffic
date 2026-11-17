# Process Traffic

See — and control — what every app on this computer talks to: which hosts, how much, how
healthy each connection is, which firewall rule let it through (or that the firewall blocked it),
and how every one of those facts was measured.

![map](screenshots/process-traffic-v1.png)

## Run

| | |
|---|---|
| `python3 networkgrafh.py` | the app (GTK 3 + WebKit2GTK 4.1). Views: **Map** (map-first, floating panels), **List**, **Firewall** (one lane per rule) — keys 1/2/3 |
| `python3 networkgrafh.py --demo` | a synthetic, clearly-labelled scenario that exercises every state |
| `python3 collector.py` | the same page in a browser at http://127.0.0.1:8765 |
| `python3 collector.py --once` | a plain-language report of everything connected, then exit |
| `python3 collector.py --explain HOST\|APP` | the sourced explanation of one host or app |
| `ptctl status \| explain X \| events -f \| block X \| block-app X \| disconnect X \| unblock X \| allow DOMAIN --reason … \| revoke NAME` | drive the **running** app from a terminal — or from Claude. Actions show in the app as "via command line" |
| `packaging/build-deb.sh` | builds `dist/process-traffic_<ver>_all.deb` |
| `python3 -m unittest discover -s tests` | tests |
| `python3 bench.py --label NAME` | performance benchmark → `perf/history.jsonl` |

Admin mode ("Your processes only ▾" in the toolbar) restarts the collector as root through polkit:
every user's processes, the firewall log, host names from DNS/TLS, and the controls.

## What it measures, and how sure it is

Every fact in the app is tagged **Exact** (read directly), **Derived** (computed from exact values),
**Inferred** (a best match that can be wrong) or **Partial** (only part is visible). The
"How it's measured" sheet (ⓘ in the toolbar) lists the rules. In short:

- **Bytes**: the kernel's per-connection TCP counters via netlink `sock_diag` (no `ss` fork), every 2 s.
  Totals count what moved since monitoring started and never go down. UDP/QUIC has no per-socket
  counters on Linux, so it's shown as "not measured" — never as 0.
- **Matched to apps**: TCP bytes (+5 % header allowance) ÷ what the interface carried, over 30 s.
- **Health**: smoothed round trip vs that connection's own best, on connections that moved data;
  plus this computer's resends over a 10 s window. Download-side loss can't be seen from here.
  Performance is yellow/orange; red is reserved for security (blocked).
- **Names**: DNS answers and TLS server names seen on the wire (admin), the local resolver log, or
  reverse DNS. **Owner / country**: DB-IP's offline ASN and country data (CC BY 4.0); cloud and CDN
  networks are flagged, and no service is ever guessed from an owner.
- **Firewall** (with `~/Projects/_machine`): the live nftables address sets name the exact rule
  that allowed an address; refusals come from the kernel log.

## Controls (admin mode)

Disconnect (closes TCP connections, then checks whether the app reconnected), block a host
(address set — warns when the address is shared), block an app (by cgroup, re-applied when the app
restarts), allow a name / remove a rule (through `machine`, logged with a reason). Blocks live in
the app's own nftables table and disappear when it quits. The Claude connection is protected: acting
on it needs an explicit second confirmation (or `ptctl --yes`).

## Files

`collector.py` (sampler, API, explanations, controls) · `sockdiag.py` (netlink) · `index.html`
(the D3 page; D3 7.9.0 is vendored) · `networkgrafh.py` (GTK shell) · `ptctl.py` · `geo.py` ·
`dnssniff.py` · `icons.py` · `catalog.json` (plain-language service/port/process names) ·
`demo.py` · `packaging/` · `design/rN/` (screenshots judged each design round) · `perf/history.jsonl`.

Data refresh (monthly): `python3 geo.py --update` — on this machine `machine enter networkgrafh:geo-update` first.
