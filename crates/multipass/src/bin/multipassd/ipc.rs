//! IPC for the menubar app: a SOCK_STREAM unix socket at
//! `/var/run/multipassd.sock`. Newline-delimited JSON — one request line in,
//! one response line out.
//!
//! # Schema (agreed with the menubar app)
//!
//! Requests from the app:
//! ```json
//! {"cmd":"status"}
//! {"cmd":"connect"}
//! {"cmd":"disconnect"}
//! ```
//!
//! Responses:
//! ```json
//! {"type":"status","connected":true,"wired":true,"wifi":true,
//!  "active_path":"wired"|"wifi"|null,"rtt_ms":12.4|null,
//!  "tx":123456,"rx":789012}
//! {"type":"ok"}
//! {"type":"error","message":"..."}
//! ```
//!
//! `active_path` is the path currently winning thread-local dedup (the one
//! the last inbound datagram arrived on) — the failover-flash signal.
//! `rtt_ms` is the active path's smoothed RTT. `tx`/`rx` are cumulative
//! tunnel bytes up/down. JSON is hand-rolled (no serde in this codebase).

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use multipass::PathKind;

use crate::Shared;

/// Socket path. The app bundles this; default is the well-known path.
pub const DEFAULT_SOCKET: &str = "/var/run/multipassd.sock";

/// Bind and serve. `shared` is the live daemon state (transport + counters).
pub async fn serve(path: &str, shared: Arc<Shared>) -> io::Result<()> {
    // Remove a stale socket from a previous run before binding.
    if std::path::Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    // The daemon runs as root but the menubar app runs as the logged-in user
    // (amos/staff). A root-owned 0755 socket is not connectable by the app
    // (EACCES), which surfaces as a permanent "daemon unavailable". Open it up:
    // this socket only exposes status + connect/disconnect, and only on the
    // local machine.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    }
    tracing::info!(%path, "ipc socket listening");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, shared).await {
                tracing::debug!(%e, "ipc connection ended");
            }
        });
    }
}

async fn handle_conn(stream: tokio::net::UnixStream, shared: Arc<Shared>) -> io::Result<()> {
    let (r, w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut writer = w;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // client hung up
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let response = handle_request(line, &shared);
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

fn handle_request(line: &str, shared: &Arc<Shared>) -> String {
    match extract_json_string(line, "cmd").as_deref() {
        Some("status") => status_json(shared),
        // connect/disconnect only flip `enabled`. The daemon's control loop
        // owns dialing, the handshake, and route setup/teardown — doing them
        // here (in the IPC handler) would race the loop and double-install
        // routes. The status reply reflects `enabled` on the next poll.
        Some("connect") => {
            shared.enabled.store(true, Ordering::Relaxed);
            "{\"type\":\"ok\"}".to_string()
        }
        Some("disconnect") => {
            shared.enabled.store(false, Ordering::Relaxed);
            "{\"type\":\"ok\"}".to_string()
        }
        _ => "{\"type\":\"error\",\"message\":\"unknown command\"}".to_string(),
    }
}

/// Build the `{"type":"status",...}` line from live state.
fn status_json(shared: &Shared) -> String {
    let connected = shared.active.load(Ordering::Relaxed);
    let paths = *shared.paths.read().unwrap();
    let active = match paths.active {
        Some(PathKind::Wired) => "\"wired\"",
        Some(PathKind::Wifi) => "\"wifi\"",
        None => "null",
    };
    // RTT of the path currently winning dedup, falling back to wired.
    let rtt_ms = match paths.active {
        Some(PathKind::Wired) => paths.wired_rtt_ms,
        Some(PathKind::Wifi) => paths.wifi_rtt_ms,
        None => paths.wired_rtt_ms,
    };
    let rtt = match rtt_ms {
        Some(v) => format!("{v:.1}"),
        None => "null".to_string(),
    };
    let tx = shared.tx_bytes.load(Ordering::Relaxed);
    let rx = shared.rx_bytes.load(Ordering::Relaxed);
    format!(
        "{{\"type\":\"status\",\"connected\":{connected},\"wired\":{},\"wifi\":{},\"active_path\":{active},\"rtt_ms\":{rtt},\"tx\":{tx},\"rx\":{rx}}}",
        paths.wired_alive, paths.wifi_alive,
    )
}

/// Minimal JSON string-field extractor: pull the value of `"key"` out of a
/// `{"key":"value"}` line. Enough for the fixed command vocabulary.
fn extract_json_string(line: &str, key: &str) -> Option<String> {
    let keypat = format!("\"{key}\"");
    let start = line.find(&keypat)? + keypat.len();
    let rest = &line[start..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let val = after.strip_prefix('"')?;
    let end = val.find('"')?;
    Some(val[..end].to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, AtomicU64};

    fn shared() -> Arc<Shared> {
        Arc::new(Shared {
            tx_bytes: AtomicU64::new(100),
            rx_bytes: AtomicU64::new(200),
            enabled: AtomicBool::new(true),
            active: AtomicBool::new(true),
            paths: std::sync::RwLock::new(crate::PathSnapshot {
                wired_alive: true,
                wifi_alive: false,
                wired_rtt_ms: Some(5.0),
                wifi_rtt_ms: None,
                active: Some(PathKind::Wired),
            }),
            server: "10.0.0.5:51823".parse().unwrap(),
            wired_src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            wifi_src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6)),
            wired_iface: "en17".into(),
            wifi_iface: "en0".into(),
            utun_name: "utun3".into(),
        })
    }

    /// The status line must match the menubar app's schema exactly:
    /// `{"type":"status","connected":..,"wired":..,"wifi":..,
    ///  "active_path":..,"rtt_ms":..,"tx":..,"rx":..}`.
    #[test]
    fn status_json_matches_contract() {
        let s = status_json(&shared());
        assert!(s.starts_with("{\"type\":\"status\""), "got: {s}");
        assert!(s.contains("\"connected\":true"), "got: {s}");
        assert!(s.contains("\"wired\":true"), "got: {s}");
        assert!(s.contains("\"wifi\":false"), "got: {s}");
        assert!(s.contains("\"active_path\":\"wired\""), "got: {s}");
        assert!(s.contains("\"rtt_ms\":5.0"), "got: {s}");
        assert!(s.contains("\"tx\":100"), "got: {s}");
        assert!(s.contains("\"rx\":200"), "got: {s}");
    }

    /// rtt_ms is null when no path has a measured RTT yet.
    #[test]
    fn status_json_null_rtt() {
        let sh = shared();
        *sh.paths.write().unwrap() = crate::PathSnapshot {
            wired_alive: true,
            wifi_alive: false,
            wired_rtt_ms: None,
            wifi_rtt_ms: None,
            active: Some(PathKind::Wired),
        };
        assert!(status_json(&sh).contains("\"rtt_ms\":null"));
    }

    /// Command routing: status returns a status line; an unknown command is
    /// an error. (connect/disconnect have route side effects and need root,
    /// so they are not exercised here.)
    #[test]
    fn command_routing() {
        let sh = shared();
        assert!(handle_request("{\"cmd\":\"status\"}", &sh).starts_with("{\"type\":\"status\""));
        assert_eq!(
            handle_request("{\"cmd\":\"bogus\"}", &sh),
            "{\"type\":\"error\",\"message\":\"unknown command\"}"
        );
    }
}
