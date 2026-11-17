# Prompt: build the macOS version of "Process Traffic"

Paste everything below the line into Claude Code on the Mac, in a folder that
contains a copy of the Linux project (`~/Projects/networkgrafh` from the Linux box:
`index.html`, `collector.py`, `geo.py`, `dnssniff.py`, `icon.svg`, `data/`). If the
copy isn't there, the spec below is complete enough to build from scratch.

---

I want a native macOS app called **Process Traffic** that matches an existing Linux app
exactly, so I have one uniform way of visualizing network traffic per process on both
machines. Build it in this folder. The Linux version is here as reference; **reuse its
`index.html` unchanged** and match its JSON contract field for field, so the two apps
look and behave the same and the page can be shared. Only the OS-specific parts (how
sockets are sampled, how DNS names are captured, the native window) should differ.

## What the app is

A window showing a live D3 v7 force-directed graph:

- **Process nodes** (coloured circles, sized by bytes moved) linked to **remote host nodes**
  (grey, labelled with a domain name when known, otherwise the IP, with a country flag).
- **Process ↔ process** links when two local processes talk over loopback (no host node).
- Link width = bytes; moving dashes = data flowing right now.
- Header: process/host counts, total ↑/↓ rate, "Total bytes / Live rate" toggle, Pause,
  "Hide this app". Hover tooltips; drag, zoom, click to focus.
- **Observer effect:** the app's own polling (window → its embedded data server) is drawn
  as two hollow grey dashed nodes, "👁 this app · data server" and "👁 this app · window",
  joined by a dotted link captioned "observer effect · polling itself every 2 s". It is
  excluded from totals and from the size scales, and "Hide this app" removes it.
- **Admin mode** (a shield button): restarts the collector with root privileges so it sees
  every user's processes and passively learns domain names from DNS answers and TLS SNI.

## Architecture (keep it identical in shape to Linux)

```
collector.py   HTTP server on 127.0.0.1:<random port>; GET /api/flows?t=<token> -> JSON below;
               serves only index.html and icon.svg; /api/quit?t=<token> shuts it down.
               Samples sockets every poll; rates = byte deltas / seconds since last sample.
backends       sampling is the ONLY OS-specific part of collector.py:
               linux: `ss -tinpH state established`; macos: see below. Pick by sys.platform.
geo.py         offline IP -> country from DB-IP "IP to Country Lite" CSV (CC BY 4.0) — reuse as is.
dnssniff.py    DNS-answer + TLS-SNI parsers (parse_dns, parse_sni) — reuse; only packet capture differs.
index.html     the D3 page — reuse unchanged.
native shell   Linux: GTK3 + WebKit2GTK (networkgrafh.py). macOS: Swift/AppKit + WKWebView .app.
```

Put the macOS sampling in the same `collector.py` behind a small backend function
(`read_sockets()` yielding the same dicts on both OSes) rather than forking the file,
so both platforms stay on one codebase.

## JSON contract (`GET /api/flows`) — must match exactly

```json
{
  "time": 1794059946.08, "interval": 1.55, "root": false, "sniff": false,
  "nodes": [
    {"id": "p:claude", "type": "process", "label": "claude", "pids": [143008],
     "sent": 1892280, "recv": 385256, "rateOut": 0.0, "rateIn": 0.0},
    {"id": "self:server", "type": "process", "label": "this app · data server",
     "self": "server", "proc": "python3", "pids": [1234], "sent": 0, "recv": 0, "rateOut": 0, "rateIn": 0},
    {"id": "self:viewer:<proc>", "type": "process", "label": "this app · window",
     "self": "viewer", "proc": "<web engine process>", "pids": [], "sent": 0, "recv": 0, "rateOut": 0, "rateIn": 0},
    {"id": "h:160.79.104.10", "type": "host", "label": "160.79.104.10", "ip": "160.79.104.10",
     "ports": ["443"], "sent": 235372, "recv": 1313511, "rateOut": 0.0, "rateIn": 0.0,
     "cc": "US", "dns": "api.anthropic.com", "nameSource": "sni", "names": ["api.anthropic.com"], "ptr": null}
  ],
  "links": [
    {"source": "p:claude", "target": "h:160.79.104.10", "conns": 4,
     "sent": 1313511, "recv": 235372, "rateOut": 0.0, "rateIn": 0.0, "self": true}
  ]
}
```

Semantics:
- Process `sent`/`recv` = bytes that process sent/received. A host node's `sent`/`recv` are from
  the **host's** point of view (host `sent` = what local processes received from it).
  Link `sent`/`recv`/`rateOut`/`rateIn` are from the **source process's** point of view.
- Processes are aggregated **by name** (`p:<name>`), all their PIDs listed.
- Rates: per connection, keyed by (pid, local addr, local port, peer addr, peer port);
  delta of byte counters since the previous sample ÷ elapsed seconds; a connection that
  appeared since the last sample counts its whole counter. Never negative.
- Loopback: if the peer address is loopback and the peer port belongs to another local
  socket, link the two process nodes directly; count each connection pair once.
- `self` tagging: a socket whose pid is the collector's own pid and whose local port is the
  collector's HTTP port → `self:server`; any loopback socket whose peer port is that HTTP
  port → `self:viewer:<proc>` (label "this app · window" when the process is the web engine,
  otherwise "<proc> (viewing this app)"). A link between two self nodes gets `"self": true`.
- Host naming priority: name captured from DNS/SNI (admin mode) → reverse DNS (async,
  cached; never block a sample) → IP. `nameSource` ∈ `dns | sni | ptr`. `cc` is an ISO
  country code, `"LAN"` for private/loopback/link-local, or null.
- `root` = collector running as root; `sniff` = DNS/SNI capture active.
- Security: bind 127.0.0.1 only; require a random per-launch token (`?t=`) on `/api/*`
  (403 otherwise); serve no files except index.html and icon.svg. The page passes its own
  `location.search` through to the API, so load it as `/?app=1&t=<token>`.

## macOS sampling backend

Linux uses `ss`, which gives per-socket byte counters and the owning process. On macOS:

1. **Byte counters per connection + process:** use `nettop` in logging mode, e.g.
   `nettop -L 1 -x -n -m tcp -J bytes_in,bytes_out` (check the exact columns on this
   macOS version with `nettop -h`; `-P` collapses to per-process, which is NOT what we
   want). Rows are process lines (`name.pid`) followed by connection lines like
   `tcp4 192.168.1.5:50123<->160.79.104.10:443`. Parse those into the same dicts the Linux
   backend yields: `proc, pid, lh, lp, ph, pp, sent, recv`. Normalise IPv4-mapped IPv6
   (`::ffff:`) and strip `%scope`. Only established TCP connections, like Linux.
2. **Fallback / cross-check:** `lsof -nP -iTCP -sTCP:ESTABLISHED` gives pid ↔ connection
   mapping (no bytes). Use it if nettop's connection lines lack something.
3. Find out (and tell me) whether nettop shows other users' processes without root; on Linux
   the non-root view is "your processes only" and the page shows a notice when `root` is false.
4. `nettop` is slow-ish to start; one invocation per 2-second poll is fine, but measure it.
   If it's over ~500 ms, keep one `nettop -L 0 -s 2` process running and parse its stream.

## macOS DNS/SNI capture (admin mode)

Reuse `parse_dns()` and `parse_sni()` from `dnssniff.py` unchanged. Replace the Linux
AF_PACKET socket with `tcpdump` (built into macOS) streaming pcap:

`tcpdump -i <iface> -U -n -w - 'udp src port 53 or (tcp and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)'`

Parse the pcap stream in Python (global header, then per-record headers; link type
EN10MB on Wi-Fi/Ethernet, NULL/LOOP on `lo0`/`utun*`), strip L2, then hand IPv4/IPv6
packets to the same logic as `Sniffer._handle`. Capture on the default-route interface
(`route -n get default` → `interface:`), plus `lo0` if a local resolver is in use.
Learned names: up to 6 per IP, most recent first, as in dnssniff.

## Native shell (macOS)

- A small Swift/AppKit app (no Electron), built with `swiftc` or a minimal Xcode project:
  one window (1200×800), a `WKWebView` loading `http://127.0.0.1:<port>/?app=1&t=<token>`,
  a toolbar with **Reload** (⌘R) and an **Admin mode** shield toggle, ⌘Q quits, title
  "Process Traffic", subtitle "your processes" / "admin · all processes · DNS capture".
- On launch it starts `collector.py --port 0 --token <random> --parent-pid <app pid>` with
  the system `python3` and reads `PORT <n>` from its stdout (the collector prints exactly
  that line first). The collector already exits when its parent pid disappears.
- Admin mode: start a second collector as root via
  `osascript -e 'do shell script "<python3> <collector.py> --port 0 --token <t> --parent-pid <pid>" with administrator privileges'`
  (or a better macOS-native elevation if you find one that doesn't need a signed helper),
  read its port the same way, and switch the web view to it; toggling off calls
  `/api/quit?t=<token>` and switches back.
- Links that leave 127.0.0.1 open in the default browser, never inside the window.
- Disable the web context menu (Back/Reload); keep Web Inspector available behind a
  `--devtools` flag.
- Add `--screenshot out.png`: open the window, wait 8 s, snapshot the window (header + web
  view via `WKWebView.takeSnapshot`), save PNG, quit.
- App icon from `icon.svg`. Output a `.app` bundle I can drag to /Applications, plus a
  one-line command to build it again.

## Done means

1. The `.app` opens a window showing my processes and their connections, with flags, live
   rates, and the observer pair styled as described; "Hide this app" works.
2. `curl` to `/api/flows` without the token returns 403; with it, JSON matching the
   contract above (show me one sample).
3. Admin mode asks for my password, then shows other users' processes and domain names
   learned from DNS/SNI for connections opened after it started.
4. `--screenshot` produces a PNG; send it to me.
5. A short README section "macOS" covering build, run, admin mode, and anything that
   differs from Linux (e.g. what nettop can and can't see without root).

Ask me before installing anything with Homebrew or pip; prefer what ships with macOS
(python3 from the Xcode Command Line Tools, swiftc, nettop, lsof, tcpdump).
