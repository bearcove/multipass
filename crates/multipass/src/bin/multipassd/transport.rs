//! The daemon's transport boundary.
//!
//! This is the single seam between `multipassd` and the multipass transport.
//! The daemon talks ONLY to the names declared here (never to `noq` directly).
//!
//! It currently implements the dual-connection active-active failover
//! transport in place, against `noq` + `multipass-proto`, mirroring the proven
//! pattern in `src/main.rs` (two independent QUIC connections, one per source
//! IP, every datagram on both, dedup by seq on the receive side).
//!
//! When `crates/multipass/src/lib.rs` lands (TransportLib) with the *same*
//! public surface, this module becomes a thin re-export:
//!
//! ```ignore
//! pub use multipass::{
//!     Transport, PathKind, PathStatus, TransportStatus, Data, TransportError,
//!     dial, transport_config, server_config, client_config, ALPN, SERVER_NAME,
//! };
//! ```
//!
//! The daemon's call sites are unchanged.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use multipass_proto::{Dedup, Frame};
use noq::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// ALPN for the multipass tunnel connection.
pub const ALPN: &[u8] = multipass_proto::ALPN;
/// TLS server name passed to noq's connect.
pub const SERVER_NAME: &str = "multipass";
/// The tunnel peer (server .1) — the utun's point-to-point destination.
pub const TUNNEL_SERVER: std::net::Ipv4Addr = multipass_proto::TUNNEL_SERVER;

/// Which physical path a connection rides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Wired,
    Wifi,
}

impl PathKind {
    pub fn label(&self) -> &'static str {
        match self {
            PathKind::Wired => "wired",
            PathKind::Wifi => "wifi",
        }
    }
}

/// Liveness/traffic counters for one path.
#[derive(Debug, Clone, Copy)]
pub struct PathStatus {
    pub alive: bool,
    pub last_recv: Option<Instant>,
    pub received: u64,
    pub transmitted: u64,
}

/// Status snapshot for both paths.
#[derive(Debug, Clone, Copy)]
pub struct TransportStatus {
    pub wired: PathStatus,
    pub wifi: PathStatus,
}

/// A deduped inbound data frame.
#[derive(Debug, Clone)]
pub struct Data {
    pub seq: u64,
    pub packet: Bytes,
    pub path: PathKind,
}

/// Transport-level errors.
#[derive(Debug)]
pub enum TransportError {
    Bind(io::Error),
    Connect(noq::ConnectError),
    Handshake(noq::ConnectionError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Bind(e) => write!(f, "bind: {e}"),
            TransportError::Connect(e) => write!(f, "connect: {e}"),
            TransportError::Handshake(e) => write!(f, "handshake: {e}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Bind(e) => Some(e),
            TransportError::Connect(e) => Some(e),
            TransportError::Handshake(e) => Some(e),
        }
    }
}

/// One path's live connection + status. The connection lives behind a `Mutex`
/// so `reconnect_path` can swap in a fresh dial without rebuilding `Transport`.
struct Path {
    kind: PathKind,
    conn: Mutex<Connection>,
    status: Mutex<PathStatus>,
}

/// The dual-connection active-active transport.
pub struct Transport {
    wired: Arc<Path>,
    wifi: Arc<Path>,
    data_rx: AsyncMutex<mpsc::Receiver<Data>>,
    ctrl_rx: AsyncMutex<mpsc::Receiver<(PathKind, Frame)>>,
    dead_rx: AsyncMutex<mpsc::Receiver<PathKind>>,
    data_tx: mpsc::Sender<Data>,
    ctrl_tx: mpsc::Sender<(PathKind, Frame)>,
    dead_tx: mpsc::Sender<PathKind>,
    dedup: Arc<Mutex<Dedup>>,
}

impl Transport {
    /// Dial both connections (wired on `wired_ip`, wifi on `wifi_ip`) and spawn
    /// their reader tasks. Fail-fast: both must come up for a valid transport.
    pub async fn connect(
        server: SocketAddr,
        wired_ip: IpAddr,
        wifi_ip: IpAddr,
    ) -> Result<Transport, TransportError> {
        let (data_tx, data_rx) = mpsc::channel(8192);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(256);
        let (dead_tx, dead_rx) = mpsc::channel(16);
        let dedup = Arc::new(Mutex::new(Dedup::new()));

        let wired = Arc::new(Path {
            kind: PathKind::Wired,
            conn: Mutex::new(dial(server, wired_ip, "wired")?),
            status: Mutex::new(PathStatus {
                alive: true,
                last_recv: None,
                received: 0,
                transmitted: 0,
            }),
        });
        let wifi = Arc::new(Path {
            kind: PathKind::Wifi,
            conn: Mutex::new(dial(server, wifi_ip, "wifi")?),
            status: Mutex::new(PathStatus {
                alive: true,
                last_recv: None,
                received: 0,
                transmitted: 0,
            }),
        });

        spawn_reader(wired.clone(), data_tx.clone(), ctrl_tx.clone(), dead_tx.clone(), dedup.clone());
        spawn_reader(wifi.clone(), data_tx.clone(), ctrl_tx.clone(), dead_tx.clone(), dedup.clone());

        Ok(Transport {
            wired,
            wifi,
            data_rx: AsyncMutex::new(data_rx),
            ctrl_rx: AsyncMutex::new(ctrl_rx),
            dead_rx: AsyncMutex::new(dead_rx),
            data_tx,
            ctrl_tx,
            dead_tx,
            dedup,
        })
    }

    /// Send one raw IP packet on BOTH live paths as `Frame::Data { seq, packet }`.
    /// Best-effort: a dead path is skipped (its `alive` flag cleared).
    pub fn send_data(&self, seq: u64, packet: Bytes) {
        self.send_frame(&Frame::Data { seq, packet });
    }

    /// Send any control frame on both paths (Hello/Assign/...).
    pub fn send_frame(&self, frame: &Frame) {
        let data = multipass_proto::encode(frame);
        for path in [&self.wired, &self.wifi] {
            let sent = path.conn.lock().send_datagram(data.clone());
            let mut st = path.status.lock();
            match sent {
                Ok(()) => {
                    st.alive = true;
                    st.transmitted = st.transmitted.saturating_add(data.len() as u64);
                }
                Err(_) => st.alive = false,
            }
        }
    }

    /// Next deduped inbound data frame. `None` = transport fully closed.
    pub async fn recv_data(&self) -> Option<Data> {
        self.data_rx.lock().await.recv().await
    }

    /// Next non-Data control frame, tagged by the path it arrived on.
    /// (Ping is auto-answered with Pong inside the transport; Pong updates
    /// liveness. Hello/Assign surface here for the daemon's handshake.)
    pub async fn recv_control(&self) -> Option<(PathKind, Frame)> {
        self.ctrl_rx.lock().await.recv().await
    }

    /// Fires when a path's connection closes / reader errors, so the daemon
    /// can re-dial it via `reconnect_path`.
    pub async fn recv_dead(&self) -> PathKind {
        self.dead_rx
            .lock()
            .await
            .recv()
            .await
            .unwrap_or(PathKind::Wired)
    }

    /// Re-dial `kind` on `server`/`src_ip`, swap it into the path, and respawn
    /// its reader task. Clears `alive` on entry.
    pub async fn reconnect_path(
        &self,
        kind: PathKind,
        server: SocketAddr,
        src_ip: IpAddr,
    ) -> Result<(), TransportError> {
        let path = match kind {
            PathKind::Wired => &self.wired,
            PathKind::Wifi => &self.wifi,
        };
        let new_conn = dial(server, src_ip, kind.label())?;
        *path.conn.lock() = new_conn.clone();
        {
            let mut st = path.status.lock();
            st.alive = false;
            st.last_recv = None;
        }
        spawn_reader(
            path.clone(),
            self.data_tx.clone(),
            self.ctrl_tx.clone(),
            self.dead_tx.clone(),
            self.dedup.clone(),
        );
        Ok(())
    }

    /// Live status snapshot for both paths.
    pub fn status(&self) -> TransportStatus {
        TransportStatus {
            wired: *self.wired.status.lock(),
            wifi: *self.wifi.status.lock(),
        }
    }

    /// Current smoothed RTT for a path, if known.
    pub fn rtt(&self, kind: PathKind) -> Option<std::time::Duration> {
        let conn = match kind {
            PathKind::Wired => &self.wired,
            PathKind::Wifi => &self.wifi,
        };
        conn.conn.lock().rtt(noq_proto::PathId::ZERO)
    }

    /// The current connection for a path (owned clone).
    pub fn connection(&self, kind: PathKind) -> Connection {
        match kind {
            PathKind::Wired => self.wired.conn.lock().clone(),
            PathKind::Wifi => self.wifi.conn.lock().clone(),
        }
    }
}

/// Open one connection on an endpoint bound to `src_ip`, labelled for logs.
pub fn dial(
    server: SocketAddr,
    src_ip: IpAddr,
    label: &str,
) -> Result<Connection, TransportError> {
    let ep = Endpoint::client(SocketAddr::new(src_ip, 0)).map_err(TransportError::Bind)?;
    ep.set_default_client_config(client_config());
    match ep.connect(server, SERVER_NAME) {
        Ok(connecting) => connecting.await.map_err(TransportError::Handshake),
        Err(e) => Err(TransportError::Connect(e)),
    }
    .map(|conn| {
        let local = conn
            .path(noq_proto::PathId::ZERO)
            .and_then(|p| p.network_path().ok());
        tracing::info!(%label, src_ip = %src_ip, local = ?local, "transport path up");
        conn
    })
}

/// Multipath transport config copied from the proven step-0 transport.
pub fn transport_config() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_multipath_paths(2);
    tc.keep_alive_interval(Some(std::time::Duration::from_millis(200)));
    Arc::new(tc)
}

/// Server config (self-signed, skip-verify peer) — exposed for symmetry/tests.
pub fn server_config() -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["multipass".into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut cfg = ServerConfig::with_single_cert(vec![der], key.into()).unwrap();
    cfg.transport_config(transport_config());
    cfg
}

#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Client config with self-signed cert skipped (matches the step-0 transport).
pub fn client_config() -> ClientConfig {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider.into())))
        .with_no_client_auth();
    let mut cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    cfg.transport_config(transport_config());
    cfg
}

/// Per-path reader task: decodes datagrams, dedups Data, answers Ping, updates
/// status, and forwards non-Data frames to the daemon. Exits + emits on
/// `dead_tx` when the connection closes.
fn spawn_reader(
    path: Arc<Path>,
    data_tx: mpsc::Sender<Data>,
    ctrl_tx: mpsc::Sender<(PathKind, Frame)>,
    dead_tx: mpsc::Sender<PathKind>,
    dedup: Arc<Mutex<Dedup>>,
) {
    tokio::spawn(async move {
        let kind = path.kind;
        let conn = path.conn.lock().clone();
        loop {
            match conn.read_datagram().await {
                Ok(buf) => {
                    {
                        let mut st = path.status.lock();
                        st.received = st.received.saturating_add(buf.len() as u64);
                        st.last_recv = Some(Instant::now());
                        st.alive = true;
                    }
                    if let Some(frame) = multipass_proto::decode(&buf) {
                        match frame {
                            Frame::Ping { nonce } => {
                                let _ = conn.send_datagram(multipass_proto::encode(
                                    &Frame::Pong { nonce },
                                ));
                            }
                            Frame::Data { seq, packet } => {
                                if dedup.lock().insert(seq) {
                                    let _ = data_tx.try_send(Data {
                                        seq,
                                        packet,
                                        path: kind,
                                    });
                                }
                            }
                            other => {
                                let _ = ctrl_tx.try_send((kind, other));
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %kind.label(), %e, "transport reader ended");
                    let _ = dead_tx.try_send(kind);
                    break;
                }
            }
        }
    });
}