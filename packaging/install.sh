#!/bin/sh
set -eu
janus_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
janus_app_root="${XDG_DATA_HOME:-$HOME/.local/share}/janus-app"
janus_bin_root="${JANUS_INSTALL_HOME:-$HOME}/.local/bin"
janus_stage=$(mktemp -d "${TMPDIR:-/tmp}/janus-install.XXXXXX")
trap 'rm -rf "$janus_stage"' EXIT HUP INT TERM
cp -R "$janus_source/Janus" "$janus_source/JanusCLI" "$janus_stage/"
mkdir -p "$janus_app_root" "$janus_bin_root" "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
# App binaries live outside platformdirs' Janus data/config/backups directory.
rm -rf "$janus_app_root/previous"
if [ -d "$janus_app_root/current" ]; then mv "$janus_app_root/current" "$janus_app_root/previous"; fi
mv "$janus_stage" "$janus_app_root/current"
ln -sfn "$janus_app_root/current/Janus/Janus" "$janus_bin_root/janus"
ln -sfn "$janus_app_root/current/JanusCLI/JanusCLI" "$janus_bin_root/janus-cli"
cat > "${XDG_DATA_HOME:-$HOME/.local/share}/applications/janus.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Janus
Comment=Local password vault
Exec="$janus_bin_root/janus"
Icon=dialog-password
Terminal=false
Categories=Utility;Security;
EOF
printf '%s\n' 'Janus installed. Open Janus from your application menu.'
