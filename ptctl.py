#!/usr/bin/env python3
"""ptctl — see and control the network through a running Process Traffic app, from a terminal
(or from Claude). Every action is recorded in the app's Activity feed as "via command line".

    ptctl status                      plain-language report of everything connected right now
    ptctl explain HOST|APP            sourced explanation of one host (name or IP) or app
    ptctl events [-f]                 recent activity; -f follows new events
    ptctl json                        the raw snapshot
    ptctl disconnect HOST|APP         close open TCP connections (apps usually reconnect)
    ptctl block HOST                  refuse new connections to that address (until unblocked / app quits)
    ptctl block-app APP               cut an app off the network, including after it restarts
    ptctl unblock HOST|APP            undo a block made in Process Traffic
    ptctl allow DOMAIN --reason TEXT [--for 1h] [--name NAME]   add a firewall rule (machine)
    ptctl revoke NAME                 remove a firewall rule (machine)

Controls need the app in admin mode. Add --yes to act on the Claude connection itself.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

ACTOR = "command line"


def find():
    uid = os.getuid()
    base = f"/run/user/{uid}" if os.path.isdir(f"/run/user/{uid}") else os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    for name in ("process-traffic-admin.json", "process-traffic.json"):
        p = os.path.join(base, name)
        try:
            with open(p) as f:
                info = json.load(f)
            os.kill(info["pid"], 0)
            return info
        except (OSError, ValueError, KeyError):
            continue
    sys.exit("Process Traffic isn't running. Start it (app launcher, or `python3 networkgrafh.py`) and try again.")


def call(info, path, body=None):
    sep = "&" if "?" in path else "?"
    url = f"http://127.0.0.1:{info['port']}/api/{path}{sep}t={info['token']}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "ptctl"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return raw.decode() if r.headers.get_content_type() == "text/plain" else json.loads(raw)
    except urllib.error.HTTPError as e:
        sys.exit(f"error {e.code}: {e.read().decode()[:300]}")


def untoken(text):
    import re
    return re.sub(r"\{t:(\d+)\}", lambda m: time.strftime("%H:%M:%S", time.localtime(int(m.group(1)))), text)


def resolve(info, target):
    ex = call(info, "explain?id=" + urllib.request.quote(target))
    if "error" in ex:
        sys.exit(ex["error"])
    return ex


def act(info, body, yes):
    body["actor"] = ACTOR
    r = call(info, "action", body)
    if r.get("needsConfirm"):
        if not yes:
            sys.exit(r["error"] + "\nRe-run with --yes to do it anyway.")
        body["force"] = True
        r = call(info, "action", body)
    if r.get("error") or r.get("ok") is False:
        sys.exit("failed: " + (r.get("error") or r.get("out", "")))
    print(json.dumps(r))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["status", "explain", "events", "json", "disconnect", "block", "block-app",
                                    "unblock", "allow", "revoke"])
    ap.add_argument("target", nargs="?")
    ap.add_argument("-f", "--follow", action="store_true")
    ap.add_argument("--reason")
    ap.add_argument("--for", dest="dur", default="1h")
    ap.add_argument("--name")
    ap.add_argument("--yes", action="store_true")
    a = ap.parse_args()
    info = find()
    if a.cmd == "status":
        print(call(info, "report"))
    elif a.cmd == "json":
        print(json.dumps(call(info, "flows"), indent=1))
    elif a.cmd == "explain":
        ex = resolve(info, a.target or sys.exit("explain what?"))
        print(ex["title"])
        v = ex.get("verdict") or {}
        if v:
            print("  " + v.get("identity", ""))
            for s in v.get("status", []):
                print(f"  [{s['tone']}] {s['text']}")
        for f in ex["facts"]:
            print(f"  - ({f['section']}) {f.get('label', '')}: {untoken(f['text'])}   [{f['kind']}: {f['source']}]")
    elif a.cmd == "events":
        seen = 0
        while True:
            for e in call(info, "flows").get("events", []):
                if e["seq"] > seen:
                    seen = e["seq"]
                    print(time.strftime("%H:%M:%S", time.localtime(e["t"])), e["text"] + (f"  (via {e['actor']})" if e.get("actor") else ""), flush=True)
            if not a.follow:
                break
            time.sleep(2)
    elif a.cmd in ("disconnect", "block", "block-app"):
        ex = resolve(info, a.target or sys.exit(f"{a.cmd} what?"))
        op = {"disconnect": "cut", "block": "block-host", "block-app": "block-app"}[a.cmd]
        act(info, {"op": op, "id": ex["id"]}, a.yes)
    elif a.cmd == "unblock":
        snap = call(info, "flows")
        t = (a.target or "").lower()
        b = next((b for b in snap["control"]["blocks"] if t in (b.get("label") or "").lower() or t == b.get("ip") or t in b["id"].lower()), None)
        if not b:
            sys.exit("no block matches " + repr(a.target))
        act(info, {"op": "unblock", "block": b["id"]}, a.yes)
    elif a.cmd == "allow":
        if not a.target or not a.reason:
            sys.exit("usage: ptctl allow DOMAIN --reason TEXT [--for 1h] [--name NAME]")
        name = a.name or a.target.split(".")[-2][:30]
        act(info, {"op": "machine-allow", "name": name, "domain": a.target, "reason": a.reason, "for": a.dur}, a.yes)
    elif a.cmd == "revoke":
        act(info, {"op": "machine-revoke", "name": a.target}, a.yes)


if __name__ == "__main__":
    main()
