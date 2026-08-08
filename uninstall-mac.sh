#!/bin/bash
# multipass — macOS uninstall. Run with:  sudo ./uninstall-mac.sh
set -euo pipefail
LABEL="rs.bearcove.multipassd"
PLIST="/Library/LaunchDaemons/$LABEL.plist"

[ "$(id -u)" -ne 0 ] && { echo "run with sudo" >&2; exit 1; }

launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
rm -f /usr/local/libexec/multipassd
rm -rf /Applications/Multipass.app
rm -f /var/run/multipassd.sock
echo "multipass removed (daemon, plist, app, socket)."
echo "Note: if the tunnel was up, its routes are torn down on daemon exit;"
echo "  if networking looks stuck, `sudo route -n flush` is the heavy hammer."
