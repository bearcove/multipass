//! multipass-server — the router side of the multipass failover VPN.
//!
//! Listens on `0.0.0.0:51823` (noq QUIC, ALPN `multipass/0`). The client
//! opens TWO independent connections (one per interface: wired + wifi); the
//! server treats them as one logical session and the client sends every Data
//! frame on both, so the server dedups inbound by `seq` (see
//! `multipass_proto::Dedup`).
//!
//! Owns a Linux TUN device on 10.10.99.0/24 (server .1, client .2). Inbound
//! frames are decapsulated and written to the TUN; outbound packets read from
//! the TUN are wrapped as Data frames and sent on every live client
//! connection (active-active redundancy, same as the proven transport).

mod tun;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use multipass_proto::{Dedup, Frame, TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_PREFIX, encode};
use noq::{Connection, Endpoint, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::QuicServerConfig;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{debug, info, warn};

/// Server bind.
const BIND_DEFAULT: &str = "0.0.0.0:51823";

/// Outbound/inbound channel capacity to/from the TUN reader/writer threads.
const TUN_CHANNEL: usize = 1024;

fn transport() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_multipath_paths(2);
    tc.keep_alive_interval(Some(Duration::from_millis(200)));
    Arc::new(tc)
}

fn server_config() -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["multipass".into()])
        .expect("generate self-signed cert");
    let der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 configuration")
        .with_no_client_auth()
        .with_single_cert(vec![der], key.into())
        .expect("server config with cert");
    tls.alpn_protocols = vec![multipass_proto::ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(tls).expect("QUIC server config");
    let mut cfg = ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport());
    cfg
}

/// One live client connection (tagged with a stable id so `send_all` and
/// `remove_conn` don't need to compare opaque noq handles).
struct LiveConn {
    id: u64,
    conn: Connection,
}

/// A single logical client session: the set of its live connections plus the
/// shared per-tunnel state (outbound seq counter, inbound dedup window).
struct Session {
    conns: RwLock<Vec<LiveConn>>,
    next_conn_id: AtomicU64,
    seq: AtomicU64,
    dedup: Mutex<Dedup>,
}

impl Session {
    fn new() -> Self {
        Self {
            conns: RwLock::new(Vec::new()),
            next_conn_id: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            dedup: Mutex::new(Dedup::new()),
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    async fn add_conn(&self, conn: Connection) -> u64 {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        self.conns.write().await.push(LiveConn { id, conn });
        debug!(id, "connection added to session");
        id
    }

    async fn remove_conn(&self, id: u64) {
        self.conns.write().await.retain(|lc| lc.id != id);
        debug!(id, "connection removed from session");
    }

    /// Send `data` on every live connection. Returns how many got it.
    /// Dead connections (ConnectionLost) are dropped from the session;
    /// transient errors (e.g. TooLarge) keep the connection.
    async fn send_all(&self, data: Bytes) -> usize {
        let mut conns = self.conns.write().await;
        let mut live: Vec<LiveConn> = Vec::with_capacity(conns.len());
        let mut sent = 0usize;
        for lc in conns.drain(..) {
            match lc.conn.send_datagram(data.clone()) {
                Ok(()) => {
                    live.push(lc);
                    sent += 1;
                }
                Err(noq::SendDatagramError::ConnectionLost(e)) => {
                    warn!(id = lc.id, %e, "connection lost while sending; dropped");
                }
                Err(e) => {
                    warn!(id = lc.id, %e, "datagram send failed; keeping connection");
                    live.push(lc);
                }
            }
        }
        *conns = live;
        sent
    }
}

/// Drive one client connection: read datagrams, decode, dispatch.
async fn conn_handler(
    conn: Connection,
    id: u64,
    session: Arc<Session>,
    to_tun: mpsc::Sender<Bytes>,
) {
    loop {
        match conn.read_datagram().await {
            Ok(d) => {
                let Some(frame) = multipass_proto::decode(&d) else {
                    debug!(id, len = d.len(), "malformed datagram dropped");
                    continue;
                };
                match frame {
                    Frame::Hello { .. } => {
                        let assign = Frame::Assign {
                            addr: TUNNEL_CLIENT,
                            prefix: TUNNEL_PREFIX,
                            mtu: TUNNEL_MTU,
                        };
                        if conn.send_datagram(encode(&assign)).is_err() {
                            break;
                        }
                        info!(id, "answered Hello: assigned",);
                    }
                    Frame::Data { seq, packet } => {
                        let is_new = session.dedup.lock().await.insert(seq);
                        if is_new && to_tun.send(packet).await.is_err() {
                            break; // TUN writer gone
                        }
                    }
                    Frame::Ping { nonce } => {
                        if conn.send_datagram(encode(&Frame::Pong { nonce })).is_err() {
                            break;
                        }
                    }
                    Frame::Pong { .. } => {}
                    Frame::Assign { .. } => {} // server never expects an assignment
                }
            }
            Err(e) => {
                debug!(id, %e, "read_datagram ended");
                break;
            }
        }
    }
}

async fn run(bind: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tun = tun::open()?;
    info!(name = %tun.name, "TUN device up");

    // Spawn a reader thread (blocking read => packets as Bytes) and a writer
    // thread (Bytes => blocking write). Channels bridge them to the async
    // core, giving backpressure instead of blocking the reactor.
    let (from_tun_tx, mut from_tun_rx) = mpsc::channel::<Bytes>(TUN_CHANNEL);
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Bytes>(TUN_CHANNEL);

    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let rfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::dup(tun.fd.as_raw_fd())) };
        let tx = from_tun_tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; TUNNEL_MTU as usize + 64];
            loop {
                let n = unsafe {
                    libc::read(
                        rfd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    warn!(%e, "TUN read error");
                    break;
                }
                if n == 0 {
                    break; // EOF
                }
                if tx
                    .blocking_send(Bytes::copy_from_slice(&buf[..n as usize]))
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    drop(from_tun_tx); // reader thread owns the only live sender

    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let wfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::dup(tun.fd.as_raw_fd())) };
        std::thread::spawn(move || {
            while let Some(pkt) = to_tun_rx.blocking_recv() {
                let mut p = &pkt[..];
                while !p.is_empty() {
                    let n = unsafe {
                        libc::write(wfd.as_raw_fd(), p.as_ptr() as *const libc::c_void, p.len())
                    };
                    if n < 0 {
                        let e = std::io::Error::last_os_error();
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            std::thread::yield_now();
                            continue;
                        }
                        warn!(%e, "TUN write error");
                        break;
                    }
                    p = &p[n as usize..];
                }
            }
        });
    }

    let server = Endpoint::server(server_config(), bind)?;
    info!(addr = %server.local_addr()?, "listening for client connections");

    let session = Arc::new(Session::new());

    loop {
        tokio::select! {
            // A new client connection (wired or wifi). Accept it into the session.
            incoming = server.accept() => {
                let Some(incoming) = incoming else { break };
                let session = session.clone();
                let to_tun = to_tun_tx.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => { warn!(%e, "handshake failed"); return; }
                    };
                    let remote = conn.path(noq_proto::PathId::ZERO)
                        .and_then(|p| p.remote_address().ok());
                    info!(remote = ?remote, "client connection established");
                    let id = session.add_conn(conn.clone()).await;
                    conn_handler(conn, id, session.clone(), to_tun).await;
                    session.remove_conn(id).await;
                    info!(id, remote = ?remote, "client connection closed");
                });
            }
            // A packet read from the TUN: send it on every live connection.
            maybe = from_tun_rx.recv() => {
                let Some(packet) = maybe else { break }; // TUN reader died
                let seq = session.next_seq();
                let data = encode(&Frame::Data { seq, packet });
                let sent = session.send_all(data).await;
                if sent == 0 {
                    warn!(seq, "tunnel packet dropped: no live client connections");
                }
            }
            else => break,
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multipass_server=info,noq=warn".parse().unwrap()),
        )
        .init();

    let bind: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| BIND_DEFAULT.to_string())
        .parse()?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(bind))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use noq::Endpoint;

    use super::server_config;

    #[tokio::test]
    async fn production_server_negotiates_wire_protocol_alpn() {
        let server = Endpoint::server(
            server_config(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client.set_default_client_config(multipass::client_config());
        let connecting = client.connect(server_addr, multipass::SERVER_NAME).unwrap();

        let (accepted, connected) =
            tokio::join!(async { server.accept().await.unwrap().await }, connecting,);
        accepted.unwrap();
        connected.unwrap();
    }
}
