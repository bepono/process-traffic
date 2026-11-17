"""Find an app's icon file from its process name via installed .desktop files and icon themes."""
import configparser
import glob
import os

DIRS = ["/usr/share/applications", "/usr/local/share/applications", "/var/lib/flatpak/exports/share/applications",
        os.path.expanduser("~/.local/share/applications"), os.path.expanduser("~/.local/share/flatpak/exports/share/applications")]
ICON_ROOTS = ["/usr/share/icons/hicolor", "/usr/local/share/icons/hicolor", os.path.expanduser("~/.local/share/icons/hicolor"),
              "/var/lib/flatpak/exports/share/icons/hicolor"]
SIZES = ["scalable", "256x256", "128x128", "96x96", "64x64", "48x48", "512x512", "32x32"]
ALIASES = {"claude-desktop": "com.anthropic.Claude", "claude": "com.anthropic.Claude", "WebKitNetworkProcess": None}

_index = None
_cache: dict[str, str | None] = {}


def _build():
    idx = {}
    for d in DIRS:
        for path in glob.glob(os.path.join(d, "*.desktop")):
            cp = configparser.RawConfigParser(strict=False, interpolation=None)
            try:
                cp.read(path, encoding="utf-8")
                e = cp["Desktop Entry"]
            except Exception:
                continue
            icon = e.get("Icon")
            if not icon:
                continue
            did = os.path.basename(path)[:-8]
            keys = {did.lower(), did.split(".")[-1].lower()}
            exe = (e.get("Exec") or "").split()
            if exe:
                keys.add(os.path.basename(exe[0].strip('"')).lower())
            if e.get("StartupWMClass"):
                keys.add(e["StartupWMClass"].lower())
            for k in keys:
                idx.setdefault(k, icon)
    return idx


def _resolve_icon(icon):
    if os.path.isabs(icon):
        return icon if os.path.exists(icon) else None
    for root in ICON_ROOTS:
        for size in SIZES:
            for ext in ("svg", "png"):
                p = os.path.join(root, size, "apps", f"{icon}.{ext}")
                if os.path.exists(p):
                    return p
    for ext in ("svg", "png", "xpm"):
        p = f"/usr/share/pixmaps/{icon}.{ext}"
        if os.path.exists(p):
            return p
    return None


def icon_for(proc: str, app: str | None = None):
    """Path to an icon file for a process name (or app id), or None."""
    global _index
    key = f"{proc}|{app}"
    if key in _cache:
        return _cache[key]
    if _index is None:
        _index = _build()
    path = None
    for cand in (ALIASES.get(proc, proc), app, proc):
        if not cand:
            continue
        icon = _index.get(cand.lower()) or _index.get(cand.split(".")[-1].lower())
        if icon:
            path = _resolve_icon(icon)
            if path:
                break
    _cache[key] = path
    return path


ALLOWED_PREFIXES = tuple(ICON_ROOTS) + ("/usr/share/pixmaps/", "/usr/share/icons/", "/opt/", "/usr/lib/", "/usr/share/")
