//! multipass transport — the reusable dual-connection (active-active) QUIC
//! transport shared by the client daemon and the failover test binary.
//!
//! # Why two connections
//!
//! noq can't pin one Endpoint to two interfaces (a single UDP socket bound to
//! one source IP; `IP_PKTINFO` is only a hint). So we run TWO independent QUIC
//! connections, one per interface (wired / wifi), each on its own Endpoint
//! bound to that interface's source IP. Every payload datagram is sent on BOTH
//! connections; the receiver dedups by sequence number. Pulling one interface
//! blackholes one connection's packets while the other keeps delivering — that
//! is the seamlessness.
//!
//! This crate is purely I/O: no TUN, no routing, no platform-specific code. It
//! is macOS + Linux agnostic. The client daemon owns the tunnel device and the
//! Hello/Assign handshake; it drives them through [`Transport::send_frame`] and
//! [`Transport::recv_control`].

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use multipass_proto::{Dedup, Frame};
use noq::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::sync::mpsc;

/// Re-export the wire format so callers don't need a second `use` path.
pub use multipass_proto;

/// ALPN for the multipass tunnel (from multipass-proto).
pub const ALPN: &[u8] = multipass_proto::ALPN;
/// TLS server name (SNI) used when dialing. The self-signed cert is generated
/// for this name; the client verifier skips validation anyway.
pub const SERVER_NAME: &str = "multipass";

/// How long to keep a connection active before surfacing it as dead if no
/// packets arrive. The daemon uses this to decide when a path has gone silent
/// (as opposed to a hard read error, which is surfaced immediately).
pub const PATH_TIMEOUT: Duration = Duration::from_secs(5);

/// Strength of the internal channels carrying inbound frames from the reader
/// tasks to the daemon's `recv_data` / `recv_control` consumers.
const CHANNEL_CAPACITY: usize = 4096;

/// Which of the two active-active connections a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    Wired,
    Wifi,
}

impl PathKind {
    /// Both paths, in a stable order.
    pub const ALL: [PathKind; 2] = [PathKind::Wired, PathKind::Wifi];

    /// Human label for logs / status.
    pub fn label(self) -> &'static str {
        match self {
            PathKind::Wired => "wired",
            PathKind::Wifi => "wifi",
        }
    }
}

/// Errors that can occur while establishing a path connection.
#[derive(Debug)]
pub enum TransportError {
    /// Could not bind the endpoint to the interface source IP.
    Bind(std::io::Error),
    /// The QUIC handshake could not be started.
    Connect(noq::ConnectError),
    /// The handshake failed or the connection was refused.
    Handshake(noq::ConnectionError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Bind(e) => write!(f, "bind endpoint: {e}"),
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

/// Shared transport configuration: permits two multipath paths and keeps the
/// connection alive with a fast keep-alive so path loss is detected quickly.
pub fn transport_config() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_multipath_paths(2);
    tc.keep_alive_interval(Some(Duration::from_millis(200)));
    Arc::new(tc)
}

/// Build a self-signed server config. Used by the failover test binary's echo
/// server; the real server crate has its own (see multipass-server).
pub fn server_config() -> ServerConfig {
    // Self-signed cert; the client intentionally skips verification.
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key.into())
        .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let mut cfg = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    cfg.transport_config(transport_config());
    cfg
}

/// A certificate verifier that accepts any server certificate (self-signed
/// dev transport). Do not use outside of this controlled tunnel.
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

/// Build the client config: SkipVerify cert validation, the multipass ALPN,
/// and the shared transport config.
pub fn client_config() -> ClientConfig {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider.into())))
        .with_no_client_auth();
    let mut qcc = QuicClientConfig::try_from(tls).unwrap();
    qcc.set_alpn_protocols(vec![ALPN.to_vec()]);

    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(transport_config());
    cfg
}

/// Open ONE connection on an endpoint bound to `src_ip` (that interface's
/// source address), targeting `server`. `label` names the path in logs.
pub async fn dial(
    server: SocketAddr,
    src_ip: IpAddr,
    label: &str,
) -> Result<Connection, TransportError> {
    let ep = Endpoint::client(SocketAddr::new(src_ip, 0)).map_err(TransportError::Bind)?;
    ep.set_default_client_config(client_config());
    let conn = ep
        .connect(server, SERVER_NAME)
        .map_err(TransportError::Connect)?
        .await
        .map_err(TransportError::Handshake)?;
    tracing::info!(path = %label, src_ip = %src_ip, %server, "connection up");
    Ok(conn)
}

/// A single live QUIC connection on one interface, with its reader task's
/// liveness bookkeeping. The connection is swappable so a dead path can be
/// re-dialed in place without tearing down the [`Transport`].
struct Path {
    kind: PathKind,
    conn: Arc<Mutex<Connection>>,
    /// Set false when the reader task hits an error / the conn closes.
    alive: Arc<AtomicBool>,
    /// Microseconds since `started` of the last datagram received.
    last_recv: Arc<AtomicU64>,
    started: Instant,
    /// Datagrams received / transmitted on this path.
    received: Arc<AtomicU64>,
    transmitted: Arc<AtomicU64>,
}

impl Path {
    fn new(kind: PathKind, conn: Connection) -> Self {
        Self {
            kind,
            conn: Arc::new(Mutex::new(conn)),
            alive: Arc::new(AtomicBool::new(true)),
            last_recv: Arc::new(AtomicU64::new(0)),
            started: Instant::now(),
            received: Arc::new(AtomicU64::new(0)),
            transmitted: Arc::new(AtomicU64::new(0)),
        }
    }

    fn status(&self) -> PathStatus {
        let micros = self.last_recv.load(Ordering::Relaxed);
        let last_recv = (micros != 0).then(|| self.started + Duration::from_micros(micros));
        PathStatus {
            alive: self.alive.load(Ordering::Relaxed),
            last_recv,
            received: self.received.load(Ordering::Relaxed),
            transmitted: self.transmitted.load(Ordering::Relaxed),
        }
    }

    fn mark_recv(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.last_recv
            .store(self.started.elapsed().as_micros() as u64, Ordering::Relaxed);
    }
}

/// Per-path liveness snapshot, for the daemon's status surface.
#[derive(Debug, Clone, Copy)]
pub struct PathStatus {
    /// True while the reader task is running (no read error / close yet).
    pub alive: bool,
    /// When the last datagram arrived on this path, if any.
    pub last_recv: Option<Instant>,
    /// Datagrams received on this path.
    pub received: u64,
    /// Datagrams transmitted on this path.
    pub transmitted: u64,
}

/// Snapshot of both paths.
#[derive(Debug, Clone, Copy)]
pub struct TransportStatus {
    pub wired: PathStatus,
    pub wifi: PathStatus,
}

impl TransportStatus {
    /// True if at least one path is alive.
    pub fn any_alive(&self) -> bool {
        self.wired.alive || self.wifi.alive
    }
}

/// A deduped inbound data frame: the first copy of a sequence number to arrive
/// (from either path), plus which path delivered it.
#[derive(Debug, Clone)]
pub struct Data {
    pub seq: u64,
    pub packet: Bytes,
    pub path: PathKind,
}

/// The client dual-connection transport.
///
/// Holds two [`Connection`]s (wired + wifi), each with a reader task that
/// decodes inbound datagrams, auto-answers Pings, and feeds the daemon-facing
/// channels. Sequence dedup is owned here via [`multipass_proto::Dedup`].
pub struct Transport {
    wired: Arc<Path>,
    wifi: Arc<Path>,
    data_rx: mpsc::Receiver<Data>,
    control_rx: mpsc::Receiver<(PathKind, Frame)>,
    dead_rx: mpsc::Receiver<PathKind>,
    // Sender clones kept so a re-dialed path can respawn its reader task.
    data_tx: mpsc::Sender<Data>,
    control_tx: mpsc::Sender<(PathKind, Frame)>,
    dead_tx: mpsc::Sender<PathKind>,
    dedup: Dedup,
}

impl Transport {
    /// Dial both paths (wired then wifi) and start their reader tasks.
    pub async fn connect(
        server: SocketAddr,
        wired_ip: IpAddr,
        wifi_ip: IpAddr,
    ) -> Result<Self, TransportError> {
        let wired_conn = dial(server, wired_ip, "wired").await?;
        let wifi_conn = dial(server, wifi_ip, "wifi").await?;
        Ok(Self::from_connections(wired_conn, wifi_conn))
    }

    /// Wrap two already-established connections. Used by the failover test and
    /// by the daemon when re-establishing a transport.
    pub fn from_connections(wired: Connection, wifi: Connection) -> Self {
        let wired = Arc::new(Path::new(PathKind::Wired, wired));
        let wifi = Arc::new(Path::new(PathKind::Wifi, wifi));

        let (data_tx, data_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (dead_tx, dead_rx) = mpsc::channel(CHANNEL_CAPACITY);

        spawn_reader(&wired, &data_tx, &control_tx, &dead_tx);
        spawn_reader(&wifi, &data_tx, &control_tx, &dead_tx);

        Self {
            wired,
            wifi,
            data_rx,
            control_rx,
            dead_rx,
            data_tx,
            control_tx,
            dead_tx,
            dedup: Dedup::new(),
        }
    }

    /// Re-dial one dead path and swap it in, respawning its reader task.
    /// The daemon calls this on [`Transport::recv_dead`]. Returns the dial
    /// error if the interface is still down; callers retry with backoff.
    pub async fn reconnect_path(
        &self,
        kind: PathKind,
        server: SocketAddr,
        src_ip: IpAddr,
    ) -> Result<(), TransportError> {
        let new_conn = dial(server, src_ip, kind.label()).await?;
        let p = self.path(kind);
        *p.conn.lock().unwrap() = new_conn;
        p.alive.store(true, Ordering::Relaxed);
        spawn_reader(p, &self.data_tx, &self.control_tx, &self.dead_tx);
        tracing::info!(path = %kind.label(), "path reconnected");
        Ok(())
    }

    /// Send a raw IP packet as a data frame on BOTH live paths. Best-effort:
    /// a path that is dead (or rejects the datagram) is skipped.
    pub fn send_data(&self, seq: u64, packet: Bytes) {
        self.send_frame(&Frame::Data { seq, packet });
    }

    /// Send a frame on BOTH live paths. Used for control (Hello, Ping, ...).
    pub fn send_frame(&self, frame: &Frame) {
        let d = multipass_proto::encode(frame);
        for p in [&self.wired, &self.wifi] {
            if !p.alive.load(Ordering::Relaxed) {
                continue;
            }
            let conn = p.conn.lock().unwrap();
            if conn.send_datagram(d.clone()).is_ok() {
                p.transmitted.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Receive the next deduped data frame. Returns `None` once the transport
    /// is fully closed (both paths dead / dropped).
    pub async fn recv_data(&mut self) -> Option<Data> {
        loop {
            let d = self.data_rx.recv().await?;
            if self.dedup.insert(d.seq) {
                return Some(d);
            }
        }
    }

    /// Receive the next non-data frame (Hello, Assign, ...) for the daemon's
    /// handshake. Pings are answered internally and never surface here.
    pub async fn recv_control(&mut self) -> Option<(PathKind, Frame)> {
        self.control_rx.recv().await
    }

    /// Wait until one path's reader task dies (read error / connection close),
    /// returning which path. The daemon re-dials that path.
    pub async fn recv_dead(&mut self) -> PathKind {
        self.dead_rx.recv().await.unwrap_or(PathKind::Wired)
    }

    /// Snapshot of both paths' liveness.
    pub fn status(&self) -> TransportStatus {
        TransportStatus {
            wired: self.wired.status(),
            wifi: self.wifi.status(),
        }
    }

    /// Path status for one path.
    pub fn path_status(&self, kind: PathKind) -> PathStatus {
        self.path(kind).status()
    }

    /// Whether the given path is currently alive.
    pub fn is_alive(&self, kind: PathKind) -> bool {
        self.path(kind).alive.load(Ordering::Relaxed)
    }

    /// Raw noq connection for a path (e.g. to await `closed()` or inspect).
    pub fn connection(&self, kind: PathKind) -> Connection {
        self.path(kind).conn.lock().unwrap().clone()
    }

    fn path(&self, kind: PathKind) -> &Arc<Path> {
        match kind {
            PathKind::Wired => &self.wired,
            PathKind::Wifi => &self.wifi,
        }
    }
}

/// Spawn a reader task for `path`: decode inbound datagrams, auto-answer
/// Pings, and distribute Data / control frames to the shared channels. On a
/// read error or connection close it marks the path dead and notifies.
///
/// `#[allow(clippy::collapsible_match)]`: clippy suggests collapsing the
/// `if …send().await.is_err() { break }` blocks into async match guards, but
/// match guards cannot be `async`, so the suggestion doesn't compile.
#[allow(clippy::collapsible_match)]
fn spawn_reader(
    path: &Arc<Path>,
    data_tx: &mpsc::Sender<Data>,
    control_tx: &mpsc::Sender<(PathKind, Frame)>,
    dead_tx: &mpsc::Sender<PathKind>,
) {
    let path = Arc::clone(path);
    let kind = path.kind;
    let conn = Arc::clone(&path.conn);
    let alive = Arc::clone(&path.alive);
    let mark_recv = {
        let p = Arc::clone(&path);
        move || p.mark_recv()
    };
    let data_tx = data_tx.clone();
    let control_tx = control_tx.clone();
    let dead_tx = dead_tx.clone();

    tokio::spawn(async move {
        loop {
            let conn = conn.lock().unwrap().clone();
            match conn.read_datagram().await {
                Ok(d) => {
                    mark_recv();
                    match multipass_proto::decode(&d) {
                        Some(Frame::Data { seq, packet }) => {
                            if data_tx
                                .send(Data { seq, packet, path: kind })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Some(Frame::Ping { nonce }) => {
                            let _ = conn.send_datagram(multipass_proto::encode(&Frame::Pong {
                                nonce,
                            }));
                        }
                        // Pong is liveness-only; last_recv already updated above.
                        Some(Frame::Pong { .. }) => {}
                        Some(other) => {
                            if control_tx.send((kind, other)).await.is_err() {
                                break;
                            }
                        }
                        None => {
                            // Malformed datagram; drop it.
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %kind.label(), %e, "path read ended");
                    alive.store(false, Ordering::Relaxed);
                    let _ = dead_tx.send(kind).await;
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Echo server: decodes inbound data frames and re-sends them (same seq),
    /// so the client sees ONE copy per seq from EACH path — perfect for
    /// proving the transport's active-active dedup.
    async fn spawn_echo_server() -> SocketAddr {
        let server = Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    loop {
                        match conn.read_datagram().await {
                            Ok(d) => {
                                if let Some(Frame::Data { seq, packet }) =
                                    multipass_proto::decode(&d)
                                {
                                    let _ = conn.send_datagram(multipass_proto::encode(
                                        &Frame::Data { seq, packet },
                                    ));
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn active_active_sends_on_both_and_dedups() {
        let addr = spawn_echo_server().await;
        // Both paths bound to loopback (distinct ephemeral source ports).
        let mut t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();

        const N: u64 = 10;
        for seq in 0..N {
            t.send_data(seq, Bytes::from_static(b"hello"));
        }

        // Each seq is delivered on BOTH paths -> 2x copies -> dedup must
        // collapse to exactly the N unique seqs.
        let mut got = Vec::new();
        for _ in 0..N {
            let d = t.recv_data().await.unwrap();
            got.push((d.seq, d.packet));
        }
        assert_eq!(got.len(), N as usize);
        for (i, (seq, pkt)) in got.iter().enumerate() {
            assert_eq!(*seq, i as u64);
            assert_eq!(pkt, &Bytes::from_static(b"hello"));
        }

        // Both paths alive and each saw at least one datagram.
        let st = t.status();
        assert!(st.wired.alive, "wired path should be alive");
        assert!(st.wifi.alive, "wifi path should be alive");
        assert!(
            st.wired.received + st.wifi.received >= N,
            "both paths should deliver copies"
        );
    }
}