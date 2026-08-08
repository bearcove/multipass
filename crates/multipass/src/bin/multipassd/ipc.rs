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
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::transport::{PathKind, Transport};
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
        Some("connect") => {
            shared.enabled.store(true, Ordering::Relaxed);
            crate::routes::setup(
                &shared.utun_name,
                shared.server.ip(),
                &shared.wired_iface,
                &shared.wifi_iface,
            );
            "{\"type\":\"ok\"}".to_string()
        }
        Some("disconnect") => {
            shared.enabled.store(false, Ordering::Relaxed);
            crate::routes::teardown(
                &shared.utun_name,
                shared.server.ip(),
                &shared.wired_iface,
                &shared.wifi_iface,
            );
            "{\"type\":\"ok\"}".to_string()
        }
        _ => "{\"type\":\"error\",\"message\":\"unknown command\"}".to_string(),
    }
}

/// Build the `{"type":"status",...}` line from live state.
fn status_json(shared: &Shared) -> String {
    let connected = shared.enabled.load(Ordering::Relaxed);
    let (wired, wifi, rtt_ms) = match shared.transport.read().unwrap().as_ref() {
        Some(t) => {
            let s = t.status();
            (s.wired.alive, s.wifi.alive, rtt_of(t, shared))
        }
        None => (false, false, None),
    };
    let active = match &*shared.active_path.read().unwrap() {
        Some(PathKind::Wired) => "\"wired\"",
        Some(PathKind::Wifi) => "\"wifi\"",
        None => "null",
    };
    let rtt = match rtt_ms {
        Some(v) => format!("{v:.1}"),
        None => "null".to_string(),
    };
    let tx = shared.tx_bytes.load(Ordering::Relaxed);
    let rx = shared.rx_bytes.load(Ordering::Relaxed);
    format!(
        "{{\"type\":\"status\",\"connected\":{connected},\"wired\":{wired},\"wifi\":{wifi},\"active_path\":{active},\"rtt_ms\":{rtt},\"tx\":{tx},\"rx\":{rx}}}"
    )
}

/// RTT (ms) of the path currently winning dedup, falling back to wired.
fn rtt_of(t: &Transport, shared: &Shared) -> Option<f64> {
    let kind = shared.active_path.read().unwrap().unwrap_or(PathKind::Wired);
    t.rtt(kind).map(|d| d.as_secs_f64() * 1000.0)
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