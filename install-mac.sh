#!/bin/bash
# multipass — macOS client install.
#
# Non-mutating oracle:
#   ./install-mac.sh --plan
#
# Real install:
#   sudo ./install-mac.sh
#
# The installer never discovers addresses or requires a live uplink. The daemon
# resolves configured interfaces and races configured gateway endpoints at
# runtime. Existing operator configuration and identity are preserved.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_SOURCE="$REPO/target/release/multipassd"
APP_SOURCE="$REPO/app/.build/release/Multipass"
APP_INFO_SOURCE="$REPO/app/Sources/Multipass/Info.plist"

LABEL="eu.bearcove.multipassd"
DAEMON_DEST="/usr/local/libexec/multipassd"
APP_DEST="/Applications/Multipass.app"
PLIST_DEST="/Library/LaunchDaemons/$LABEL.plist"
CONFIG_DIR="/Library/Application Support/Multipass"
CONFIG_DEST="$CONFIG_DIR/config.json"
KEY_DIR="/var/db/multipass"
KEY_DEST="$KEY_DIR/client.key"
IPC_SOCKET="/var/run/multipassd.sock"
LOG_PATH="/var/log/multipassd.log"

# Documentation-only initial values. Operators replace these in the root-owned
# config before connecting. Reinstall never overwrites an existing config.
DEFAULT_GATEWAY_ID="jax"
DEFAULT_SERVER_PUBLIC_KEY="ed25519:ERERERERERERERERERERERERERERERERERERERERERE"
DEFAULT_LAN_ENDPOINT="192.0.2.1:51823"
DEFAULT_PUBLIC_IPV4_ENDPOINT="198.51.100.23:51823"
DEFAULT_PUBLIC_IPV6_ENDPOINT="[2001:db8:1088:1c17::1]:51823"
DEFAULT_CLIENT_ID="scooter"

usage() {
    cat <<EOF
usage: $0 [--plan]

  --plan  Print and validate the source-owned installation contract without
          requiring root, built artifacts, network interfaces, or live uplinks.
  no arg  Install built artifacts and create missing persistent state as root.

Existing $CONFIG_DEST and $KEY_DEST are always preserved.
EOF
}

MODE="install"
case "${1:-}" in
    "") ;;
    --plan|--validate) MODE="plan" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { usage >&2; exit 2; }

print_plan() {
    cat <<EOF
multipass macOS installation plan (non-mutating):
  daemon source      : $DAEMON_SOURCE
  daemon destination : $DAEMON_DEST (root:wheel 0755)
  app source         : $APP_SOURCE
  app destination    : $APP_DEST
  config              : $CONFIG_DEST (root:wheel 0600)
  client private key : $KEY_DEST (root:wheel 0600)
  LaunchDaemon plist : $PLIST_DEST (root:wheel 0644)
  launch arguments   : $DAEMON_DEST --config $CONFIG_DEST
  IPC socket         : $IPC_SOCKET (from config, created by daemon)
  daemon log         : $LOG_PATH
  identity policy    : create the client key only when absent; never print or overwrite it
  config policy      : create a documentation-default config only when absent; preserve operator endpoints, uplinks, pinned server key, and client identity on reinstall
  uplink policy      : zero currently usable uplinks is accepted; enabled VPN intent waits for configured interfaces and races LAN/public endpoints when they appear
  uninstall policy   : binaries, app, plist, and runtime socket are removed; config and client identity are preserved unless explicitly purged
EOF
}

if [ "$MODE" = "plan" ]; then
    print_plan
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo:  sudo $0" >&2
    exit 1
fi

[ -x "$DAEMON_SOURCE" ] || { echo "missing $DAEMON_SOURCE — run: cargo build --release -p multipass --bin multipassd" >&2; exit 1; }
[ -x "$APP_SOURCE" ] || { echo "missing $APP_SOURCE — run: (cd app && swift build -c release)" >&2; exit 1; }
[ -f "$APP_INFO_SOURCE" ] || { echo "missing $APP_INFO_SOURCE" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "missing openssl; cannot create Ed25519 client identity" >&2; exit 1; }

atomic_install_file() {
    local source="$1"
    local destination="$2"
    local mode="$3"
    local directory temporary
    directory="$(dirname "$destination")"
    mkdir -p "$directory"
    temporary="$(mktemp "$directory/.multipass-install.XXXXXX")"
    install -m "$mode" -o root -g wheel "$source" "$temporary"
    if ! mv -f "$temporary" "$destination"; then
        rm -f "$temporary"
        return 1
    fi
}

atomic_write_stdin() {
    local destination="$1"
    local mode="$2"
    local directory temporary
    directory="$(dirname "$destination")"
    mkdir -p "$directory"
    temporary="$(mktemp "$directory/.multipass-install.XXXXXX")"
    cat > "$temporary"
    chmod "$mode" "$temporary"
    chown root:wheel "$temporary"
    if ! mv -f "$temporary" "$destination"; then
        rm -f "$temporary"
        return 1
    fi
}

mkdir -p "$KEY_DIR" "$CONFIG_DIR"
chmod 700 "$KEY_DIR"
chmod 755 "$CONFIG_DIR"
chown root:wheel "$KEY_DIR" "$CONFIG_DIR"

if [ -e "$KEY_DEST" ]; then
    [ -f "$KEY_DEST" ] && [ ! -L "$KEY_DEST" ] || { echo "refusing unsafe existing client key path: $KEY_DEST" >&2; exit 1; }
    chmod 600 "$KEY_DEST"
    chown root:wheel "$KEY_DEST"
    echo "preserving existing client identity at $KEY_DEST"
else
    KEY_TEMP="$(mktemp "$KEY_DIR/.client-key.XXXXXX")"
    trap 'rm -f "${KEY_TEMP:-}" "${APP_INFO_TEMP:-}" "${PLIST_TEMP:-}"' EXIT
    chmod 600 "$KEY_TEMP"
    chown root:wheel "$KEY_TEMP"
    openssl genpkey -algorithm ED25519 -outform DER -out "$KEY_TEMP"
    if ! mv "$KEY_TEMP" "$KEY_DEST"; then
        rm -f "$KEY_TEMP"
        exit 1
    fi
    KEY_TEMP=""
    echo "created client identity at $KEY_DEST (private material not displayed)"
fi

if [ -e "$CONFIG_DEST" ]; then
    [ -f "$CONFIG_DEST" ] && [ ! -L "$CONFIG_DEST" ] || { echo "refusing unsafe existing config path: $CONFIG_DEST" >&2; exit 1; }
    chmod 600 "$CONFIG_DEST"
    chown root:wheel "$CONFIG_DEST"
    echo "preserving existing operator config at $CONFIG_DEST"
else
    atomic_write_stdin "$CONFIG_DEST" 600 <<EOF
{
  "gateway": {
    "id": "$DEFAULT_GATEWAY_ID",
    "server_public_key": "$DEFAULT_SERVER_PUBLIC_KEY",
    "endpoints": [
      { "address": "$DEFAULT_LAN_ENDPOINT", "display_name": "Home LAN" },
      { "address": "$DEFAULT_PUBLIC_IPV4_ENDPOINT", "display_name": "Public IPv4" },
      { "address": "$DEFAULT_PUBLIC_IPV6_ENDPOINT", "display_name": "Public IPv6" }
    ]
  },
  "client": {
    "id": "$DEFAULT_CLIENT_ID",
    "private_key_file": "$KEY_DEST"
  },
  "uplinks": [],
  "ipc_socket": "$IPC_SOCKET"
}
EOF
    echo "created $CONFIG_DEST with zero uplinks and documentation endpoints"
    echo "edit the root-owned config with the deployment's pinned server key, endpoints, and uplinks before connecting"
fi

atomic_install_file "$DAEMON_SOURCE" "$DAEMON_DEST" 755

PLIST_TEMP="$(mktemp "${TMPDIR:-/tmp}/multipass-launchd.XXXXXX.plist")"
cat > "$PLIST_TEMP" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DAEMON_DEST</string>
        <string>--config</string>
        <string>$CONFIG_DEST</string>
    </array>
    <key>RunAtLoad</key><false/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$LOG_PATH</string>
    <key>StandardErrorPath</key><string>$LOG_PATH</string>
</dict>
</plist>
EOF
atomic_install_file "$PLIST_TEMP" "$PLIST_DEST" 644
rm -f "$PLIST_TEMP"
PLIST_TEMP=""

APP_INFO_TEMP="$(mktemp "${TMPDIR:-/tmp}/multipass-info.XXXXXX.plist")"
cp "$APP_INFO_SOURCE" "$APP_INFO_TEMP"
GIT_COMMIT="$(/usr/bin/git -C "$REPO" rev-parse HEAD)"
/usr/libexec/PlistBuddy -c "Set :MultipassGitCommit $GIT_COMMIT" "$APP_INFO_TEMP"
APP_STAGE="$(mktemp -d "/Applications/.Multipass.app.XXXXXX")"
trap 'rm -f "${KEY_TEMP:-}" "${APP_INFO_TEMP:-}" "${PLIST_TEMP:-}"; rm -rf "${APP_STAGE:-}" "${APP_BACKUP:-}"' EXIT
mkdir -p "$APP_STAGE/Contents/MacOS" "$APP_STAGE/Contents/Resources"
install -m 755 -o root -g wheel "$APP_SOURCE" "$APP_STAGE/Contents/MacOS/Multipass"
install -m 644 -o root -g wheel "$APP_INFO_TEMP" "$APP_STAGE/Contents/Info.plist"
APP_BACKUP=""
if [ -e "$APP_DEST" ]; then
    APP_BACKUP="$(mktemp -d "/Applications/.Multipass.previous.XXXXXX")"
    rmdir "$APP_BACKUP"
    mv "$APP_DEST" "$APP_BACKUP"
fi
if ! mv "$APP_STAGE" "$APP_DEST"; then
    [ -z "$APP_BACKUP" ] || mv "$APP_BACKUP" "$APP_DEST"
    exit 1
fi
APP_STAGE=""
if [ -n "$APP_BACKUP" ]; then
    rm -rf "$APP_BACKUP"
    APP_BACKUP=""
fi
rm -f "$APP_INFO_TEMP"
APP_INFO_TEMP=""

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DEST"
launchctl enable "system/$LABEL"

echo
echo "installed. The daemon is loaded but VPN intent remains OFF until you open"
echo "Multipass and choose Connect. It is valid to remain enabled with zero ready uplinks."
echo "Config: $CONFIG_DEST"
echo "Logs: $LOG_PATH"
echo "To uninstall while preserving config and identity: sudo $REPO/uninstall-mac.sh"
