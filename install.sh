#!/bin/sh
# Adds "Process Traffic" to your desktop's app launcher (current user only).
# Undo with: ./install.sh --uninstall
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
ID=io.github.networkgrafh

if [ "$1" = "--uninstall" ]; then
  rm -f "$APPS/$ID.desktop" "$ICONS/$ID.svg"
  echo "Removed."; exit 0
fi

mkdir -p "$APPS" "$ICONS"
cp "$DIR/icon.svg" "$ICONS/$ID.svg"
cat > "$APPS/$ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Process Traffic
Comment=Live graph of network data transfer by process
Exec=python3 "$DIR/networkgrafh.py"
Icon=$ID
Terminal=false
Categories=System;Monitor;
StartupWMClass=$ID
EOF
update-desktop-database "$APPS" 2>/dev/null || true
echo "Installed: look for \"Process Traffic\" in your app launcher."
