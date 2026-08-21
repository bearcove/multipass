#!/bin/bash
# multipass — macOS uninstall. Run with: sudo ./uninstall-mac.sh [--purge]
#
# By default, persistent operator configuration and the client identity remain
# installed so a later reinstall preserves the same pinned mutual identity.

set -euo pipefail

LABEL="eu.bearcove.multipassd"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
CONFIG_DIR="/Library/Application Support/Multipass"
KEY_DIR="/var/db/multipass"

PURGE=false
case "${1:-}" in
    "") ;;
    --purge) PURGE=true ;;
    -h|--help)
        echo "usage: sudo $0 [--purge]"
        echo "  default: remove runtime artifacts and preserve config/client identity"
        echo "  --purge: also permanently remove config and client identity"
        exit 0
        ;;
    *) echo "usage: sudo $0 [--purge]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo "usage: sudo $0 [--purge]" >&2; exit 2; }

[ "$(id -u)" -ne 0 ] && { echo "run with sudo" >&2; exit 1; }

launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
rm -f /usr/local/libexec/multipassd
rm -rf /Applications/Multipass.app
rm -f /var/run/multipassd.sock

if [ "$PURGE" = true ]; then
    rm -rf "$CONFIG_DIR" "$KEY_DIR"
    echo "multipass removed, including persistent configuration and client identity."
else
    echo "multipass removed (daemon, plist, app, runtime socket)."
    echo "Preserved operator config: $CONFIG_DIR/config.json"
    echo "Preserved client identity: $KEY_DIR/client.key"
    echo "Use sudo $0 --purge only when permanent identity/config deletion is intended."
fi

echo "Note: if the tunnel was up, its routes are torn down on daemon exit;"
echo "  if networking looks stuck, \`sudo route -n flush\` is the heavy hammer."
