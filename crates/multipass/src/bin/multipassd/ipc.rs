//! Newline-delimited JSON IPC for the menubar app.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use facet::Facet;
use multipass_proto::TUNNEL_SERVER;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::state::{Shared, UplinkSnapshot};

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
struct StatusUplink {
    id: String,
    display_name: String,
    interface: String,
    configured_enabled: bool,
    state: String,
    ready: bool,
    source_address: Option<String>,
    gateway_endpoint: Option<String>,
    rtt_ms: Option<f64>,
    tx: u64,
    rx: u64,
    last_error: Option<String>,
}

impl From<UplinkSnapshot> for StatusUplink {
    fn from(uplink: UplinkSnapshot) -> Self {
        Self {
            id: uplink.id.to_string(),
            display_name: uplink.display_name,
            interface: uplink.interface,
            configured_enabled: uplink.configured_enabled,
            state: uplink.state.as_str().into(),
            ready: uplink.ready,
            source_address: uplink.source_address.map(|address| address.to_string()),
            gateway_endpoint: uplink.gateway_endpoint.map(|endpoint| endpoint.to_string()),
            rtt_ms: uplink.rtt_ms,
            tx: uplink.tx,
            rx: uplink.rx,
            last_error: uplink.last_error,
        }
    }
}

#[derive(Debug, Facet)]
struct BenchmarkPath {
    id: String,
    display_name: String,
    interface: String,
    source_address: Option<String>,
}

#[allow(dead_code, reason = "fields are read reflectively by facet-json")]
#[derive(Debug, Facet)]
#[repr(u8)]
#[facet(tag = "type", rename_all = "snake_case")]
enum Reply {
    Status {
        enabled: bool,
        connected: bool,
        active_uplink_id: Option<String>,
        tx: u64,
        rx: u64,
        uplinks: Vec<StatusUplink>,
    },
    BenchmarkTopology {
        protocol_version: u32,
        daemon_version: String,
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

pub async fn serve(server: IpcServer, shared: Arc<Shared>) -> io::Result<()> {
    loop {
        let (stream, _peer) = server.listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_conn(stream, shared).await {
                tracing::debug!(%error, "ipc connection ended");
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
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        writer
            .write_all(handle_request(line, &shared).as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
}

fn handle_request(line: &str, shared: &Shared) -> String {
    let reply = match facet_json::from_str::<Request>(line) {
        Ok(Request {
            cmd: Command::Status,
        }) => status_reply(shared),
        Ok(Request {
            cmd: Command::Connect,
        }) => {
            shared.connect();
            Reply::Ok
        }
        Ok(Request {
            cmd: Command::Disconnect,
        }) => {
            shared.disconnect();
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
    let snapshot = shared.snapshot();
    Reply::Status {
        enabled: snapshot.enabled,
        connected: snapshot.connected,
        active_uplink_id: snapshot.active_uplink_id.map(|id| id.to_string()),
        tx: snapshot.tx,
        rx: snapshot.rx,
        uplinks: snapshot.uplinks.into_iter().map(Into::into).collect(),
    }
}

fn benchmark_topology_reply(shared: &Shared) -> Reply {
    let snapshot = shared.snapshot();
    Reply::BenchmarkTopology {
        protocol_version: 2,
        daemon_version: env!("MULTIPASS_BUILD_COMMIT").into(),
        server_version: shared.authenticated_server_version(),
        underlay_target: shared
            .config
            .gateway
            .endpoints
            .first()
            .map(|endpoint| endpoint.address.ip().to_string())
            .unwrap_or_default(),
        tunnel_ipv4_target: Some(TUNNEL_SERVER.to_string()),
        tunnel_ipv6_target: shared
            .tunnel_ipv6_server()
            .map(|address| address.to_string()),
        listener_base_port: 5210,
        listener_count: 16,
        paths: snapshot
            .uplinks
            .into_iter()
            .map(|uplink| BenchmarkPath {
                id: uplink.id.to_string(),
                display_name: uplink.display_name,
                interface: uplink.interface,
                source_address: uplink.source_address.map(|address| address.to_string()),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    use multipass::config::{
        ClientConfig, ClientIdentityConfig, GatewayConfig, GatewayEndpoint, UplinkConfig,
    };
    use multipass::identity::PublicKey;
    use multipass::{ClientId, UplinkId};

    use crate::state::UplinkState;

    fn config() -> ClientConfig {
        ClientConfig {
            gateway: GatewayConfig {
                id: "jax".into(),
                server_public_key: PublicKey::parse(
                    "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                endpoints: vec![GatewayEndpoint {
                    address: "10.0.0.5:51823".parse().unwrap(),
                    display_name: Some("LAN".into()),
                }],
            },
            client: ClientIdentityConfig {
                id: ClientId::new("scooter").unwrap(),
                private_key_file: "/var/db/multipass/client.key".into(),
            },
            uplinks: vec![
                UplinkConfig {
                    id: UplinkId::new("desk-ethernet").unwrap(),
                    display_name: "Desk Ethernet".into(),
                    interface: "en17".into(),
                    enabled: true,
                },
                UplinkConfig {
                    id: UplinkId::new("wifi").unwrap(),
                    display_name: "Wi-Fi".into(),
                    interface: "en0".into(),
                    enabled: true,
                },
            ],
            ipc_socket: "/var/run/multipassd.sock".into(),
        }
    }

    fn shared_with_tx(tx: u64) -> Arc<Shared> {
        let shared = Shared::new(&config(), "utun3".into());
        shared.tx_bytes.store(tx, Ordering::Relaxed);
        shared.rx_bytes.store(200, Ordering::Relaxed);
        shared.connect();
        let ethernet = UplinkId::new("desk-ethernet").unwrap();
        shared
            .update_uplink(&ethernet, |uplink| {
                uplink.state = UplinkState::Ready;
                uplink.ready = true;
                uplink.source_address = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
                uplink.gateway_endpoint = Some("10.0.0.5:51823".parse().unwrap());
                uplink.rtt_ms = Some(5.0);
                uplink.tx = 11_000;
                uplink.rx = 12_000;
            })
            .unwrap();
        shared.activate("test-server".into(), Some("2001:db8::1".parse().unwrap()));
        shared.set_active(Some(ethernet));
        shared
    }

    fn shared() -> Arc<Shared> {
        shared_with_tx(100)
    }

    #[test]
    fn status_reply_matches_dynamic_contract_and_order() {
        let json = handle_request("{\"cmd\":\"status\"}", &shared());
        let reply: Reply = facet_json::from_str(&json).unwrap();
        let Reply::Status {
            enabled,
            connected,
            active_uplink_id,
            tx,
            rx,
            uplinks,
        } = reply
        else {
            panic!("expected status reply");
        };
        assert!(enabled);
        assert!(connected);
        assert_eq!(active_uplink_id.as_deref(), Some("desk-ethernet"));
        assert_eq!((tx, rx), (100, 200));
        assert_eq!(uplinks.len(), 2);
        assert_eq!(uplinks[0].id, "desk-ethernet");
        assert_eq!(uplinks[0].state, "ready");
        assert_eq!(uplinks[0].source_address.as_deref(), Some("192.168.1.5"));
        assert_eq!(uplinks[1].id, "wifi");
        assert_eq!(uplinks[1].state, "waiting_for_address");
        assert_eq!(uplinks[1].source_address, None);
    }

    #[test]
    fn connect_expresses_intent_without_claiming_connectivity() {
        let shared = Shared::new(&config(), "utun3".into());
        let reply: Reply =
            facet_json::from_str(&handle_request("{\"cmd\":\"connect\"}", &shared)).unwrap();
        assert!(matches!(reply, Reply::Ok));
        let snapshot = shared.snapshot();
        assert!(snapshot.enabled);
        assert!(!snapshot.connected);
        assert_eq!(snapshot.uplinks[0].state, UplinkState::WaitingForAddress);
    }

    #[test]
    fn disconnect_clears_authenticated_runtime() {
        let shared = shared();
        let reply: Reply =
            facet_json::from_str(&handle_request("{\"cmd\":\"disconnect\"}", &shared)).unwrap();
        assert!(matches!(reply, Reply::Ok));
        assert!(!shared.enabled.load(Ordering::Relaxed));
        assert_eq!(shared.authenticated_server_version(), "unknown");
        assert!(!shared.snapshot().connected);
    }

    #[test]
    fn benchmark_topology_preserves_order_and_nullable_source() {
        let shared = shared();
        let reply: Reply =
            facet_json::from_str(&handle_request("{\"cmd\":\"benchmark_topology\"}", &shared))
                .unwrap();
        let Reply::BenchmarkTopology {
            protocol_version,
            server_version,
            underlay_target,
            tunnel_ipv4_target,
            tunnel_ipv6_target,
            paths,
            ..
        } = reply
        else {
            panic!("expected benchmark topology reply");
        };
        assert_eq!(protocol_version, 2);
        assert_eq!(server_version, "test-server");
        assert_eq!(underlay_target, "10.0.0.5");
        assert_eq!(tunnel_ipv4_target.as_deref(), Some("10.10.99.1"));
        assert_eq!(tunnel_ipv6_target.as_deref(), Some("2001:db8::1"));
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].id, "desk-ethernet");
        assert_eq!(paths[0].source_address.as_deref(), Some("192.168.1.5"));
        assert_eq!(paths[1].id, "wifi");
        assert_eq!(paths[1].source_address, None);
    }

    #[test]
    fn command_routing() {
        let reply: Reply =
            facet_json::from_str(&handle_request("{\"cmd\":\"bogus\"}", &shared())).unwrap();
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
        let first = tokio::spawn(serve(bind(&path).unwrap(), shared_with_tx(100)));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while tokio::net::UnixStream::connect(&path).await.is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first IPC server must become reachable");

        let error = match bind(&path) {
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
