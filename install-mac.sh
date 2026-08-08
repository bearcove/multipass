#!/bin/bash
# multipass — macOS client install. Run with:  sudo ./install-mac.sh
#
# What this does as root, and why:
#   1. Copies the multipassd daemon to /usr/local/libexec/multipassd
#      (needs root to create the utun device + manage routes at runtime).
#   2. Installs a LaunchDaemon so multipassd starts at boot and restarts on
#      crash. This is the ONLY always-on root component.
#   3. Copies the Multipass menubar app to /Applications (plain user app).
#
# It does NOT: touch DNS, install a NetworkExtension, add login items behind
# your back, or phone anywhere. The daemon only talks to your router over two
# QUIC connections (wired + wifi). Read the daemon source in
# crates/multipass/src/bin/multipassd/ before you run this if you like.
#
# Auto-detects your wired + wifi IPv4 addresses and the default gateway
# (assumed to be the router running multipass-server). Override via env:
#   MULTIPASS_SERVER=10.10.10.1:51823 MULTIPASS_WIRED_IF=en17 MULTIPASS_WIFI_IF=en0 sudo ./install-mac.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_BIN="$REPO/target/release/multipassd"
APP_BIN="$REPO/app/.build/release/Multipass"
LABEL="rs.bearcove.multipassd"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
LIBEXEC="/usr/local/libexec"

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo:  sudo $0" >&2
    exit 1
fi

# --- locate binaries ---
[ -x "$DAEMON_BIN" ] || { echo "missing $DAEMON_BIN — run: cargo build --release -p multipass --bin multipassd" >&2; exit 1; }
[ -x "$APP_BIN" ] || { echo "missing $APP_BIN — run: (cd app && swift build -c release)" >&2; exit 1; }

# --- figure out wired + wifi interfaces and their IPs ---
WIFI_IF="${MULTIPASS_WIFI_IF:-en0}"
WIRED_IF="${MULTIPASS_WIRED_IF:-}"

ip_of() { ipconfig getifaddr "$1" 2>/dev/null || true; }

WIFI_IP="$(ip_of "$WIFI_IF")"
if [ -z "$WIRED_IF" ]; then
    # first active non-wifi interface with an IPv4 address
    for i in $(ifconfig -l); do
        [ "$i" = "$WIFI_IF" ] && continue
        case "$i" in en*) ;; *) continue;; esac
        a="$(ip_of "$i")"
        if [ -n "$a" ]; then WIRED_IF="$i"; WIRED_IP="$a"; break; fi
    done
else
    WIRED_IP="$(ip_of "$WIRED_IF")"
fi

# --- server: default gateway (the router) ---
GW="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')"
SERVER="${MULTIPASS_SERVER:-$GW:51823}"

echo "multipass install plan:"
echo "  wired iface : ${WIRED_IF:-<none>}  ip=${WIRED_IP:-<none>}"
echo "  wifi  iface : $WIFI_IF  ip=${WIFI_IP:-<none>}"
echo "  server      : $SERVER"
echo "  daemon      : $LIBEXEC/multipassd (LaunchDaemon $LABEL)"
echo "  app         : /Applications/Multipass.app"
echo

if [ -z "${WIRED_IP:-}" ] || [ -z "${WIFI_IP:-}" ]; then
    echo "ERROR: need both a wired and a wifi IPv4 address up right now." >&2
    echo "  (wired=${WIRED_IF:-?}/${WIRED_IP:-none}  wifi=$WIFI_IF/${WIFI_IP:-none})" >&2
    echo "  plug in Ethernet / join Wi-Fi, or set MULTIPASS_WIRED_IF / MULTIPASS_WIFI_IF." >&2
    exit 1
fi
if [ -z "$GW" ] && [ -z "${MULTIPASS_SERVER:-}" ]; then
    echo "ERROR: no default gateway found and MULTIPASS_SERVER not set." >&2
    exit 1
fi

# --- install daemon ---
mkdir -p "$LIBEXEC"
install -m 755 -o root -g wheel "$DAEMON_BIN" "$LIBEXEC/multipassd"

# --- LaunchDaemon plist ---
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$LIBEXEC/multipassd</string>
        <string>$SERVER</string>
        <string>$WIRED_IP</string>
        <string>$WIFI_IP</string>
    </array>
    <key>RunAtLoad</key><false/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/var/log/multipassd.log</string>
    <key>StandardErrorPath</key><string>/var/log/multipassd.log</string>
</dict>
</plist>
PLIST
chmod 644 "$PLIST"; chown root:wheel "$PLIST"

# --- install app as a .app bundle ---
APP_DIR="/Applications/Multipass.app/Contents"
mkdir -p "$APP_DIR/MacOS" "$APP_DIR/Resources"
install -m 755 "$APP_BIN" "$APP_DIR/MacOS/Multipass"
[ -f "$REPO/app/Sources/Multipass/Info.plist" ] && install -m 644 "$REPO/app/Sources/Multipass/Info.plist" "$APP_DIR/Info.plist"

# --- load daemon (not started until you toggle connect in the app) ---
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"

echo
echo "installed. The daemon is loaded but the tunnel is OFF until you open"
echo "Multipass and toggle Connect. Logs: /var/log/multipassd.log"
echo "To uninstall: sudo $REPO/uninstall-mac.sh"
