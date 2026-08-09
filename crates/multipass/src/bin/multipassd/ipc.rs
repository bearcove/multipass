//! IPC for the menubar app: a SOCK_STREAM unix socket at
//! `/var/run/multipassd.sock`. Newline-delimited JSON — one typed request in,
//! one typed response out, serialized with facet-json.
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
//! the last inbound datagram arrived on). `tx`/`rx` are cumulative tunnel
//! bytes up/down.

use facet::Facet;
use multipass_proto::{TUNNEL_SERVER, TUNNEL_V6_SERVER};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use multipass::PathKind;

use crate::Shared;

/// Socket path. The app bundles this; default is the well-known path.
pub const DEFAULT_SOCKET: &str = "/var/run/multipassd.sock";

#[derive(Debug, Facet)]
#[repr(u8)]
#[facet(rename_all = "snake_case")]
enum Command {
    Status,
    Connect,
    Disconnect,
    BenchmarkTopology,
}

#[derive(Debug, Facet)]
struct Request {
    cmd: Command,
}

#[derive(Debug, Facet)]
struct BenchmarkPath {
    id: String,
    display_name: String,
    interface: String,
    source_address: String,
}

#[allow(dead_code, reason = "fields are read reflectively by facet-json")]
#[derive(Debug, Facet)]
#[repr(u8)]
#[facet(tag = "type", rename_all = "snake_case")]
enum Reply {
    Status {
        connected: bool,
        wired: bool,
        wifi: bool,
        active_path: Option<String>,
        rtt_ms: Option<f64>,
        tx: u64,
        rx: u64,
    },
    BenchmarkTopology {
        protocol_version: u32,
        server_version: String,
        underlay_target: String,
        tunnel_ipv4_target: Option<String>,
        tunnel_ipv6_target: Option<String>,
        listener_base_port: u16,
        listener_count: u16,
        paths: Vec<BenchmarkPath>,
    },
    Ok,
    Error {
        message: String,
    },
}

pub struct IpcServer {
    listener: UnixListener,
    _socket_lock: File,
}

/// Claim the singleton lock and bind IPC before creating dataplane resources.
pub fn bind(path: &str) -> io::Result<IpcServer> {
    let socket_lock = acquire_socket_lock(path)?;
    if std::path::Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    }
    tracing::info!(%path, "ipc socket listening");
    Ok(IpcServer {
        listener,
        _socket_lock: socket_lock,
    })
}

/// Serve an already-bound listener. An accept failure is fatal to the daemon.
pub async fn serve(server: IpcServer, shared: Arc<Shared>) -> io::Result<()> {
    loop {
        let (stream, _peer) = server.listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, shared).await {
                tracing::debug!(%e, "ipc connection ended");
            }
        });
    }
}

fn acquire_socket_lock(path: &str) -> io::Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(format!("{path}.lock"))?;
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(lock);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "another multipassd owns the IPC socket",
        ))
    } else {
        Err(error)
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
            break;
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

fn handle_request(line: &str, shared: &Shared) -> String {
    let reply = match facet_json::from_str::<Request>(line) {
        Ok(Request {
            cmd: Command::Status,
        }) => status_reply(shared),
        Ok(Request {
            cmd: Command::Connect,
        }) => {
            shared.enabled.store(true, Ordering::Relaxed);
            Reply::Ok
        }
        Ok(Request {
            cmd: Command::Disconnect,
        }) => {
            shared.enabled.store(false, Ordering::Relaxed);
            Reply::Ok
        }
        Ok(Request {
            cmd: Command::BenchmarkTopology,
        }) => benchmark_topology_reply(shared),
        Err(_) => Reply::Error {
            message: "unknown command".into(),
        },
    };
    facet_json::to_string(&reply).expect("IPC reply schema must serialize")
}

fn status_reply(shared: &Shared) -> Reply {
    let connected = shared.active.load(Ordering::Relaxed);
    let paths = *shared.paths.read().unwrap();
    let active_path = paths.active.map(|path| path.label().to_string());
    let rtt_ms = match paths.active {
        Some(PathKind::Wired) => paths.wired_rtt_ms,
        Some(PathKind::Wifi) => paths.wifi_rtt_ms,
        None => paths.wired_rtt_ms,
    };
    Reply::Status {
        connected,
        wired: paths.wired_alive,
        wifi: paths.wifi_alive,
        active_path,
        rtt_ms,
        tx: shared.tx_bytes.load(Ordering::Relaxed),
        rx: shared.rx_bytes.load(Ordering::Relaxed),
    }
}

fn benchmark_topology_reply(shared: &Shared) -> Reply {
    Reply::BenchmarkTopology {
        protocol_version: 1,
        server_version: "unknown".into(),
        underlay_target: shared.server.ip().to_string(),
        tunnel_ipv4_target: Some(TUNNEL_SERVER.to_string()),
        tunnel_ipv6_target: Some(TUNNEL_V6_SERVER.to_string()),
        listener_base_port: 5210,
        listener_count: 16,
        paths: vec![
            BenchmarkPath {
                id: "wired".into(),
                display_name: "Wired".into(),
                interface: shared.wired_iface.clone(),
                source_address: shared.wired_src.to_string(),
            },
            BenchmarkPath {
                id: "wifi".into(),
                display_name: "Wi-Fi".into(),
                interface: shared.wifi_iface.clone(),
                source_address: shared.wifi_src.to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, AtomicU64};

    fn shared_with_tx(tx: u64) -> Arc<Shared> {
        Arc::new(Shared {
            tx_bytes: AtomicU64::new(tx),
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

    fn shared() -> Arc<Shared> {
        shared_with_tx(100)
    }

    #[test]
    fn status_reply_matches_contract() {
        let json = handle_request("{\"cmd\":\"status\"}", &shared());
        let reply: Reply = facet_json::from_str(&json).unwrap();
        match reply {
            Reply::Status {
                connected,
                wired,
                wifi,
                active_path,
                rtt_ms,
                tx,
                rx,
            } => {
                assert!(connected);
                assert!(wired);
                assert!(!wifi);
                assert_eq!(active_path.as_deref(), Some("wired"));
                assert_eq!(rtt_ms, Some(5.0));
                assert_eq!(tx, 100);
                assert_eq!(rx, 200);
            }
            other => panic!("expected status reply, got {other:?}"),
        }
    }

    #[test]
    fn status_reply_preserves_unknown_rtt() {
        let sh = shared();
        *sh.paths.write().unwrap() = crate::PathSnapshot {
            wired_alive: true,
            wifi_alive: false,
            wired_rtt_ms: None,
            wifi_rtt_ms: None,
            active: Some(PathKind::Wired),
        };
        let json = handle_request("{\"cmd\":\"status\"}", &sh);
        let reply: Reply = facet_json::from_str(&json).unwrap();
        assert!(matches!(reply, Reply::Status { rtt_ms: None, .. }));
    }

    #[test]
    fn benchmark_topology_matches_contract() {
        let json = handle_request("{\"cmd\":\"benchmark_topology\"}", &shared());
        let reply: Reply = facet_json::from_str(&json).unwrap();
        match reply {
            Reply::BenchmarkTopology {
                protocol_version,
                server_version,
                underlay_target,
                tunnel_ipv4_target,
                tunnel_ipv6_target,
                listener_base_port,
                listener_count,
                paths,
            } => {
                assert_eq!(protocol_version, 1);
                assert_eq!(server_version, "unknown");
                assert_eq!(underlay_target, "10.0.0.5");
                assert_eq!(tunnel_ipv4_target.as_deref(), Some("10.10.99.1"));
                assert_eq!(tunnel_ipv6_target.as_deref(), Some("fd00:99::1"));
                assert_eq!(listener_base_port, 5210);
                assert_eq!(listener_count, 16);
                assert_eq!(paths.len(), 2);
                assert_eq!(paths[0].id, "wired");
                assert_eq!(paths[0].display_name, "Wired");
                assert_eq!(paths[0].interface, "en17");
                assert_eq!(paths[0].source_address, "192.168.1.5");
                assert_eq!(paths[1].id, "wifi");
                assert_eq!(paths[1].display_name, "Wi-Fi");
                assert_eq!(paths[1].interface, "en0");
                assert_eq!(paths[1].source_address, "192.168.1.6");
            }
            other => panic!("expected benchmark topology reply, got {other:?}"),
        }
    }

    #[test]
    fn benchmark_topology_round_trips_interface_names() {
        let sh = shared();
        let mut sh = Arc::try_unwrap(sh).ok().unwrap();
        sh.wired_iface = "en\"17\\uplink".into();
        let json = facet_json::to_string(&benchmark_topology_reply(&sh)).unwrap();
        let reply: Reply = facet_json::from_str(&json).unwrap();
        let Reply::BenchmarkTopology { paths, .. } = reply else {
            panic!("expected benchmark topology reply");
        };
        assert_eq!(paths[0].interface, "en\"17\\uplink");
    }

    #[test]
    fn command_routing() {
        let json = handle_request("{\"cmd\":\"bogus\"}", &shared());
        let reply: Reply = facet_json::from_str(&json).unwrap();
        assert!(matches!(reply, Reply::Error { message } if message == "unknown command"));
    }

    #[tokio::test]
    async fn second_server_cannot_replace_live_socket() {
        let base = std::env::temp_dir().join(format!(
            "multipassd-ipc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = base.to_str().unwrap().to_owned();
        let first_path = path.clone();
        let first_server = bind(&first_path).unwrap();
        let first = tokio::spawn(async move { serve(first_server, shared_with_tx(100)).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while tokio::net::UnixStream::connect(&path).await.is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first IPC server must become reachable");

        let second_path = path.clone();
        let error = match bind(&second_path) {
            Ok(_) => panic!("second IPC bind unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);

        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream.write_all(b"{\"cmd\":\"status\"}\n").await.unwrap();
        let mut response = String::new();
        BufReader::new(stream)
            .read_line(&mut response)
            .await
            .unwrap();
        assert!(
            response.contains("\"tx\":100"),
            "socket was stolen: {response}"
        );

        first.abort();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }
}
