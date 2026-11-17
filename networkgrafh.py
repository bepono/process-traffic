#!/usr/bin/env python3
"""Native desktop app: GTK window + WebKit view around the process traffic graph.

Normal mode runs the collector in-process as your user. The shield button
("Admin mode") starts a second collector through pkexec as root, which sees
every process and captures DNS answers / TLS server names to label hosts;
the window then switches to it. Requires python3-gi and gir1.2-webkit2-4.1.
"""
import argparse
import json
import os
import secrets
import time
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gdk, Gio, GLib, Gtk, WebKit2  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collector  # noqa: E402

APP_ID = "io.github.networkgrafh"
ROOT_HELPER = "/usr/libexec/process-traffic/collector-root"   # installed by the .deb; polkit describes it properly
HERE = os.path.dirname(os.path.abspath(__file__))


OPTS = argparse.Namespace(demo=False, demo_scale=1, interval=2.0, no_sniff=True, token=None)


def start_local_server(token) -> str:
    OPTS.token = token
    collector.setup(OPTS)
    collector.SAMPLER.start()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), collector.Handler)
    collector.SELF_PORTS.add(str(srv.server_address[1]))
    collector.write_runtime(srv.server_address[1])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/?app=1&t={token}"


class AdminCollector:
    """Root collector started via pkexec; reports its port on stdout."""

    def __init__(self, on_ready, on_exit):
        self.token = secrets.token_urlsafe(16)
        self.url = None
        self.on_ready, self.on_exit = on_ready, on_exit
        self.proc = Gio.Subprocess.new(
            ["pkexec", *(([ROOT_HELPER]) if os.path.exists(ROOT_HELPER) else [sys.executable, os.path.join(HERE, "collector.py")]),
             "--port", "0", "--token", self.token, "--parent-pid", str(os.getpid())],
            Gio.SubprocessFlags.STDOUT_PIPE,
        )
        self.out = Gio.DataInputStream.new(self.proc.get_stdout_pipe())
        self.out.read_line_async(GLib.PRIORITY_DEFAULT, None, self._on_line)
        self.proc.wait_async(None, self._on_exit)

    def _on_line(self, stream, res):
        try:
            line, _ = stream.read_line_finish_utf8(res)
        except GLib.Error:
            return
        if line is None:
            return
        if line.startswith("PORT ") and not self.url:
            self.url = f"http://127.0.0.1:{line.split()[1]}/?app=1&t={self.token}"
            self.on_ready(self)
        stream.read_line_async(GLib.PRIORITY_DEFAULT, None, self._on_line)

    def _on_exit(self, proc, res):
        proc.wait_finish(res)
        self.on_exit(self)

    def stop(self):
        if not self.url:
            return
        url = self.url.replace("/?app=1&", "/api/quit?")
        threading.Thread(target=lambda: _quiet(urllib.request.urlopen, url, timeout=2), daemon=True).start()


def _quiet(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        pass


class Window(Gtk.ApplicationWindow):
    def __init__(self, app, url):
        super().__init__(application=app, title="Process Traffic")
        self.set_default_size(*SIZE)
        icon = os.path.join(HERE, "icon.svg")
        if os.path.exists(icon):
            self.set_icon_from_file(icon)
        self.local_url, self.admin, self._syncing = url, None, False

        self.header = Gtk.HeaderBar(show_close_button=True, title="Process Traffic")
        # admin mode is switched from the page's toolbar ("Your processes only" button) via a message handler
        self.admin_btn = Gtk.ToggleButton()   # state holder only; not shown
        self.admin_btn.connect("toggled", self.on_admin_toggled)
        self.set_titlebar(self.header)

        settings = WebKit2.Settings(
            enable_developer_extras="--devtools" in sys.argv,
            enable_write_console_messages_to_stdout=True,
        )
        settings.set_user_agent_with_application_details("ProcessTraffic", collector.VERSION)
        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("pt")
        ucm.connect("script-message-received::pt", self.on_page_message)
        self.view = WebKit2.WebView(settings=settings, user_content_manager=ucm)
        self.view.connect("decide-policy", self.on_policy)
        if "--devtools" not in sys.argv:
            self.view.connect("context-menu", lambda *_: True)
        self.add(self.view)
        self.show_mode(None)

        accel = Gtk.AccelGroup()
        accel.connect(Gdk.keyval_from_name("r"), Gdk.ModifierType.CONTROL_MASK, 0,
                      lambda *_: self.view.reload() or True)
        accel.connect(Gdk.keyval_from_name("q"), Gdk.ModifierType.CONTROL_MASK, 0,
                      lambda *_: app.quit() or True)
        self.add_accel_group(accel)
        self.connect("destroy", lambda *_: self.admin and self.admin.stop())

    # ----- admin mode -----
    def set_toggle(self, active):
        self._syncing = True
        self.admin_btn.set_active(active)
        self._syncing = False

    def on_page_message(self, _ucm, result):
        try:
            msg = result.get_js_value().to_string()
        except Exception:
            return
        if msg == "admin" and os.geteuid() != 0 and self.admin_btn.get_sensitive():
            self.admin_btn.set_active(not self.admin_btn.get_active())

    def show_mode(self, admin):
        self.view.load_uri(admin.url if admin else self.local_url)

    def on_admin_toggled(self, btn):
        if self._syncing:
            return
        if btn.get_active():
            btn.set_sensitive(False)  # until pkexec answers
            self.admin = AdminCollector(self.on_admin_ready, self.on_admin_exit)
        elif self.admin:
            admin, self.admin = self.admin, None
            admin.stop()
            self.show_mode(None)

    def on_admin_ready(self, admin):
        if admin is self.admin:
            self.admin_btn.set_sensitive(True)
            self.show_mode(admin)

    def on_admin_exit(self, admin):
        if admin is not self.admin:
            return  # we stopped it ourselves
        was_running = admin.url is not None
        self.admin = None
        self.admin_btn.set_sensitive(True)
        self.set_toggle(False)
        if was_running:
            self.show_mode(None)

    # ----- navigation -----
    def on_policy(self, view, decision, kind):
        # keep the window on the local collector pages; open anything else in the browser
        if kind == WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            uri = decision.get_navigation_action().get_request().get_uri()
            if not uri.startswith("http://127.0.0.1:"):
                decision.ignore()
                Gio.AppInfo.launch_default_for_uri(uri, None)
                return True
        return False


def capture(win, path, app):
    """Save header bar + web view to a PNG, then quit (Wayland can't read back window pixels,
    so the page comes from WebKit's own snapshot; needs python3-gi-cairo)."""
    import cairo

    def done(view, res):
        try:
            web = view.get_snapshot_finish(res)
            hdr = win.get_titlebar()
            hh = hdr.get_allocated_height()
            w = max(hdr.get_allocated_width(), web.get_width())
            surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, w, hh + web.get_height())
            cr = cairo.Context(surf)
            hdr.draw(cr)
            cr.set_source_surface(web, 0, hh)
            cr.paint()
            surf.write_to_png(path)
            print(f"saved {path} ({surf.get_width()}x{surf.get_height()})")
        except Exception as e:
            print(f"screenshot failed: {e}", file=sys.stderr)
        app.quit()

    win.view.get_snapshot(WebKit2.SnapshotRegion.VISIBLE, WebKit2.SnapshotOptions.NONE, None, done)
    return False


def webkit_rss():
    """Resident memory of this app's web engine processes (MB)."""
    total = 0
    me = os.getpid()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            if not comm.startswith("WebKit"):
                continue
            with open(f"/proc/{pid}/environ", "rb") as f:
                env = f.read()
            if f"PT_OWNER={me}".encode() not in env:
                continue
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
        except OSError:
            continue
    return round(total / 1024, 1)


def self_rss():
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 1)


def bench(win, app, out):
    def done(view, res):
        try:
            page = json.loads(view.evaluate_javascript_finish(res).to_string())
        except Exception as e:
            page = {"error": str(e)}
        t = list(collector.SAMPLER.timing)
        snap = collector.SAMPLER.snapshot
        result = {
            "page": page,
            "collector": {"sampleMs_avg": round(sum(x[1] for x in t) / len(t), 2), "sampleMs_max": round(max(x[1] for x in t), 2),
                          "ssMs_avg": round(sum(x[0] for x in t) / len(t), 2), "samples": len(t),
                          "sockets": snap["perf"]["sockets"], "nodes": len(snap["nodes"]), "links": len(snap["links"]),
                          "jsonKB": round(len(collector.SAMPLER.snapshot_json()) / 1024, 1)},
            "memoryMB": {"app_python": self_rss(), "webkit": webkit_rss()},
            "cpu_s": {"app_process": round(sum(os.times()[:2]), 2)},
        }
        with open(out, "w") as f:
            json.dump(result, f, indent=1)
        print(json.dumps(result, indent=1))
        app.quit()
    win.view.evaluate_javascript("JSON.stringify(window.__pt.perf())", -1, None, None, None, done)
    return False


class App(Gtk.Application):
    def __init__(self, shot=None, delay=8, nonunique=False):
        flags = Gio.ApplicationFlags.NON_UNIQUE if nonunique else Gio.ApplicationFlags.FLAGS_NONE
        super().__init__(application_id=APP_ID, flags=flags)
        self.url, self.shot, self.delay = None, shot, delay

    def do_activate(self):
        if self.props.active_window:
            self.props.active_window.present()
            return
        if not self.url:
            self.url = start_local_server(secrets.token_urlsafe(16))
        win = Window(self, self.url)
        win.show_all()
        if self.shot:  # let the force layout settle and a couple of samples arrive
            GLib.timeout_add_seconds(self.delay, capture, win, self.shot, self)
        if BENCH:
            GLib.timeout_add_seconds(BENCH[0], bench, win, self, BENCH[1])
        if PAGE_JS:
            win.view.connect("load-changed", lambda v, ev: ev == WebKit2.LoadEvent.FINISHED and
                             GLib.timeout_add(1500, lambda: v.evaluate_javascript(PAGE_JS, -1, None, None, None, None, None) and False))


BENCH = None
PAGE_JS = None


def main():
    global BENCH, PAGE_JS
    ap = argparse.ArgumentParser(description="Process Traffic — see and control what your computer talks to")
    ap.add_argument("--demo", action="store_true", help="show a synthetic, labelled scenario")
    ap.add_argument("--demo-scale", type=int, default=1)
    ap.add_argument("--screenshot", metavar="PNG", help="save a screenshot after --delay seconds and quit")
    ap.add_argument("--delay", type=int, default=8)
    ap.add_argument("--size", default="1280x820", help="window size WxH")
    ap.add_argument("--js", help="JavaScript to run in the page after load (screenshots of a given state)")
    ap.add_argument("--bench", metavar="JSON", help="run --delay seconds, write performance numbers, quit")
    ap.add_argument("--devtools", action="store_true")
    ap.add_argument("--dark", action="store_true", help="force the dark appearance")
    ap.add_argument("--version", action="version", version=collector.VERSION)
    a = ap.parse_args()
    OPTS.demo, OPTS.demo_scale = a.demo, a.demo_scale
    os.environ["PT_OWNER"] = str(os.getpid())   # lets --bench find our web engine processes
    if a.bench:
        BENCH = (a.delay, os.path.abspath(a.bench))
    PAGE_JS = a.js
    global SIZE
    SIZE = tuple(int(x) for x in a.size.split("x"))
    GLib.set_prgname(APP_ID)
    GLib.set_application_name("Process Traffic")
    if a.dark:
        Gtk.Settings.get_default().set_property("gtk-application-prefer-dark-theme", True)
    shot = os.path.abspath(a.screenshot) if a.screenshot else None
    sys.exit(App(shot, a.delay, nonunique=bool(shot or a.bench)).run([sys.argv[0]]))


SIZE = (1280, 820)


if __name__ == "__main__":
    main()
