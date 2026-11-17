#!/bin/sh
# Build dist/process-traffic_<version>_all.deb from this folder.  Usage: packaging/build-deb.sh
set -e
SRC="$(cd "$(dirname "$0")/.." && pwd)"
VER=$(python3 -c "import sys; sys.path.insert(0, '$SRC'); import collector; print(collector.VERSION)" 2>/dev/null)
OUT="$SRC/dist"; ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
APP="$ROOT/usr/share/process-traffic"
install -d "$APP/vendor" "$APP/data" "$ROOT/usr/bin" "$ROOT/usr/libexec/process-traffic" "$ROOT/DEBIAN" \
  "$ROOT/usr/share/applications" "$ROOT/usr/share/icons/hicolor/scalable/apps" "$ROOT/usr/share/metainfo" \
  "$ROOT/usr/share/polkit-1/actions" "$ROOT/usr/share/doc/process-traffic"
for f in collector.py networkgrafh.py geo.py dnssniff.py sockdiag.py icons.py demo.py ptctl.py catalog.json index.html icon.svg; do
  install -m 644 "$SRC/$f" "$APP/$f"
done
install -m 644 "$SRC/vendor/d3.v7.9.0.min.js" "$APP/vendor/"
install -m 644 "$SRC"/data/*.csv.gz "$APP/data/"
printf '#!/bin/sh\nexec python3 /usr/share/process-traffic/networkgrafh.py "$@"\n' > "$ROOT/usr/bin/process-traffic"
printf '#!/bin/sh\nexec python3 /usr/share/process-traffic/ptctl.py "$@"\n' > "$ROOT/usr/bin/ptctl"
printf '#!/bin/sh\n# Root collector started through pkexec by Process Traffic (polkit action io.github.networkgrafh.admin)\nexec /usr/bin/python3 -I /usr/share/process-traffic/collector.py "$@"\n' > "$ROOT/usr/libexec/process-traffic/collector-root"
chmod 755 "$ROOT/usr/bin/process-traffic" "$ROOT/usr/bin/ptctl" "$ROOT/usr/libexec/process-traffic/collector-root"
install -m 644 "$SRC/packaging/io.github.networkgrafh.desktop" "$ROOT/usr/share/applications/"
install -m 644 "$SRC/icon.svg" "$ROOT/usr/share/icons/hicolor/scalable/apps/io.github.networkgrafh.svg"
install -m 644 "$SRC/packaging/io.github.networkgrafh.metainfo.xml" "$ROOT/usr/share/metainfo/"
install -m 644 "$SRC/packaging/io.github.networkgrafh.policy" "$ROOT/usr/share/polkit-1/actions/"
install -m 644 "$SRC/LICENSE" "$ROOT/usr/share/doc/process-traffic/copyright"
SIZE=$(du -sk "$ROOT/usr" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<CTL
Package: process-traffic
Version: $VER
Section: net
Priority: optional
Architecture: all
Installed-Size: $SIZE
Depends: python3 (>= 3.11), python3-gi, gir1.2-gtk-3.0, gir1.2-webkit2-4.1, iproute2, pkexec | policykit-1
Recommends: nftables, python3-gi-cairo
Maintainer: Process Traffic authors <noreply@example.invalid>
Description: see and control what every app on your computer talks to
 A live map of which apps talk to which internet hosts, how much data moves,
 how healthy each connection is, and which firewall rule allowed it. Every
 number says how it was measured. Disconnect, block hosts or apps, and drive
 it from the command line with ptctl.
CTL
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$ROOT" "$OUT/process-traffic_${VER}_all.deb" >/dev/null
echo "$OUT/process-traffic_${VER}_all.deb"
