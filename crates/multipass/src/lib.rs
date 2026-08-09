//! multipass transport — the reusable dual-connection (active-active) QUIC
//! transport shared by the client daemon and the failover test binary.
//!
//! # Why two connections
//!
//! noq can't pin one Endpoint to two interfaces (a single UDP socket bound to
//! one source IP; `IP_PKTINFO` is only a hint). So we run TWO independent QUIC
//! connections, one per interface (wired / wifi), each on its own Endpoint
//! bound to that interface's source IP.
//!
//! # Send policy: active-active replication
//!
//! Every payload datagram is sent on every authenticated live connection with
//! the same sequence number. The receiver accepts the first copy and dedups
//! later copies via [`multipass_proto::Dedup`]. This spends extra bandwidth to
//! preserve TCP and UDP sessions across link changes without a detection gap.
//!
//! This crate is purely I/O: no TUN, no routing, no platform-specific code. It
//! is macOS + Linux agnostic. The client daemon owns the tunnel device and the
//! Hello/Assign handshake; it drives them through [`Transport::send_frame_on`]
//! and [`Transport::recv_control`].

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
pub use multipass_proto::{PathKind, Scheduler, SendWindow};

/// ALPN for the multipass tunnel (from multipass-proto).
pub const ALPN: &[u8] = multipass_proto::ALPN;
/// TLS server name (SNI) used when dialing. The self-signed cert is generated
/// for this name; the client verifier skips validation anyway.
pub const SERVER_NAME: &str = "multipass";

/// How often the transport sends a Ping probe on each live path to measure RTT.
pub const RTT_PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// A probe with no Pong reply after this long is considered lost.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Strength of the internal channels carrying inbound frames from the reader
/// tasks to the daemon's `recv_data` / `recv_control` consumers.
const CHANNEL_CAPACITY: usize = 4096;

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
    tc.max_idle_timeout(Some(PROBE_TIMEOUT.try_into().expect("valid idle timeout")));
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
/// liveness/RTT bookkeeping. The connection is swappable so a dead path can be
/// re-dialed in place without tearing down the [`Transport`].
struct Path {
    kind: PathKind,
    conn: Arc<Mutex<Connection>>,
    /// Set false when the reader task hits an error / the conn closes.
    alive: Arc<AtomicBool>,
    /// True after this connection acknowledges the current client epoch.
    ready: Arc<AtomicBool>,
    /// Microseconds since `started` of the last datagram received (0 = none).
    last_recv: Arc<AtomicU64>,
    /// Last measured RTT in microseconds (0 = none).
    rtt: Arc<AtomicU64>,
    /// In-flight Ping probe: (connection generation, nonce, sent-at), if any.
    probe: Arc<Mutex<Option<(u64, u64, Instant)>>>,
    /// Monotonic nonce source for Ping probes.
    probe_nonce: Arc<AtomicU64>,
    /// Incremented whenever a connection is replaced. Reader failures from an
    /// older generation must not kill the newly installed path.
    generation: Arc<AtomicU64>,
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
            ready: Arc::new(AtomicBool::new(false)),
            last_recv: Arc::new(AtomicU64::new(0)),
            rtt: Arc::new(AtomicU64::new(0)),
            probe: Arc::new(Mutex::new(None)),
            probe_nonce: Arc::new(AtomicU64::new(0)),
            generation: Arc::new(AtomicU64::new(0)),
            started: Instant::now(),
            received: Arc::new(AtomicU64::new(0)),
            transmitted: Arc::new(AtomicU64::new(0)),
        }
    }

    fn status(&self) -> PathStatus {
        let last_recv = micros_to_instant(self.started, self.last_recv.load(Ordering::Relaxed));
        let rtt = {
            let m = self.rtt.load(Ordering::Relaxed);
            (m != 0).then(|| Duration::from_micros(m))
        };
        PathStatus {
            alive: self.alive.load(Ordering::Relaxed),
            last_recv,
            rtt,
            received: self.received.load(Ordering::Relaxed),
            transmitted: self.transmitted.load(Ordering::Relaxed),
        }
    }

    fn mark_recv(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.last_recv
            .store(self.started.elapsed().as_micros() as u64, Ordering::Relaxed);
    }

    fn set_rtt(&self, rtt: Duration) {
        self.rtt.store(rtt.as_micros() as u64, Ordering::Relaxed);
    }

    fn mark_dead(&self, generation: u64) -> bool {
        {
            let connection = self.conn.lock().unwrap();
            if self.generation.load(Ordering::Acquire) != generation {
                return false;
            }
            if self
                .alive
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }
            self.ready.store(false, Ordering::Release);
            connection.close(0u32.into(), b"path liveness timeout");
        }
        *self.probe.lock().unwrap() = None;
        true
    }
}

fn micros_to_instant(started: Instant, micros: u64) -> Option<Instant> {
    (micros != 0).then(|| started + Duration::from_micros(micros))
}

/// Per-path liveness snapshot, for the daemon's status surface.
#[derive(Debug, Clone, Copy)]
pub struct PathStatus {
    /// True while the reader task is running (no read error / close yet).
    pub alive: bool,
    /// When the last datagram arrived on this path, if any.
    pub last_recv: Option<Instant>,
    /// Last measured round-trip time on this path, if any.
    pub rtt: Option<Duration>,
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
/// channels. A probe loop measures per-path RTT for status. Outbound data is
/// replicated across every authenticated live path; inbound data is deduped by
/// [`multipass_proto::Dedup`].
pub struct Transport {
    wired: Arc<Path>,
    wifi: Arc<Path>,
    // Receivers are mutex-guarded so `recv_*` can take `&self` and be selected
    // over alongside `send_data` in one tokio::select!.
    data_rx: tokio::sync::Mutex<mpsc::Receiver<Data>>,
    control_rx: tokio::sync::Mutex<mpsc::Receiver<(PathKind, Frame)>>,
    dead_rx: tokio::sync::Mutex<mpsc::Receiver<PathKind>>,
    // Sender clones kept so a re-dialed path can respawn its reader task.
    data_tx: mpsc::Sender<Data>,
    control_tx: mpsc::Sender<(PathKind, Frame)>,
    dead_tx: mpsc::Sender<PathKind>,
    dedup: Mutex<Dedup>,
    /// Receive scoreboard for server→client packets; generates SACKs.
    recv_scoreboard: Mutex<multipass_proto::SackScoreboard>,
    probe_task: tokio::task::JoinHandle<()>,
    // Aggregation state: retained unacked packets + path scheduler.
    send_window: Mutex<SendWindow>,
    scheduler: Mutex<Scheduler>,
}

impl Transport {
    /// Dial both paths (wired then wifi) and start their reader + probe tasks.
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

        for p in [&wired, &wifi] {
            spawn_reader(p, &data_tx, &control_tx, &dead_tx);
        }
        let probe_task = spawn_probe(&wired, &wifi, &dead_tx);

        Self {
            wired,
            wifi,
            data_rx: tokio::sync::Mutex::new(data_rx),
            control_rx: tokio::sync::Mutex::new(control_rx),
            dead_rx: tokio::sync::Mutex::new(dead_rx),
            data_tx,
            control_tx,
            dead_tx,
            dedup: Mutex::new(Dedup::new()),
            recv_scoreboard: Mutex::new(multipass_proto::SackScoreboard::new()),
            probe_task,
            send_window: Mutex::new(SendWindow::new(CHANNEL_CAPACITY)),
            scheduler: Mutex::new(Scheduler::new()),
        }
    }
    /// Install a newly dialed connection for one dead path and respawn its
    /// reader. Dialing itself stays outside the packet pump so a failed
    /// handshake cannot block traffic on the surviving path.
    pub fn install_reconnected_path(&self, kind: PathKind, new_conn: Connection) {
        let p = self.path(kind);
        {
            let mut connection = p.conn.lock().unwrap();
            p.alive.store(false, Ordering::Release);
            p.generation.fetch_add(1, Ordering::AcqRel);
            *connection = new_conn;
            p.ready.store(false, Ordering::Relaxed);
            p.rtt.store(0, Ordering::Relaxed);
            p.alive.store(true, Ordering::Release);
        }
        *p.probe.lock().unwrap() = None;
        spawn_reader(p, &self.data_tx, &self.control_tx, &self.dead_tx);
        tracing::info!(path = %kind.label(), "path reconnected");
    }

    /// Send a raw IP packet on the best available path, retaining it for
    /// possible retransmission until the peer's SACK confirms receipt.
    ///
    /// Aggregation: the packet goes out on ONE path chosen by the scheduler.
    /// The SendWindow keeps a copy; on SACK gap or path death the same `seq`
    /// is retransmitted on a surviving path. The receiver dedups by `seq`, so
    /// retransmission never produces a duplicate at the tunnel.
    ///
    /// Returns `true` if the packet was queued on a path (retained regardless
    /// of the local send outcome). Returns `false` only if no path is ready.
    pub fn send_data(&self, seq: u64, packet: Bytes) -> bool {
        // A packet that can never fit a datagram is rejected outright; no path
        // could ever carry it, so retaining it would wedge the window.
        let encoded = multipass_proto::encode(&Frame::Data {
            seq,
            packet: packet.clone(),
        });
        let fits_any = PathKind::ALL.iter().any(|&kind| {
            self.connection(kind)
                .max_datagram_size()
                .map(|max| encoded.len() <= max)
                .unwrap_or(false)
        });
        if !fits_any {
            return false;
        }

        // Update scheduler eligibility from current path state.
        {
            let mut sched = self.scheduler.lock().unwrap();
            for kind in PathKind::ALL {
                sched.set_eligible(kind, self.is_ready(kind) && self.is_alive(kind));
                let rtt = self.path(kind).rtt.load(Ordering::Relaxed);
                if rtt > 0 {
                    sched.note_rtt(kind, Duration::from_micros(rtt));
                }
                let space = self
                    .path(kind)
                    .conn
                    .lock()
                    .unwrap()
                    .datagram_send_buffer_space();
                sched.note_queue_space(kind, space);
            }
        }

        // Retain before send so a path failure never loses the only copy.
        self.send_window.lock().unwrap().insert(seq, packet);

        let kind = {
            let mut sched = self.scheduler.lock().unwrap();
            sched.pick()
        };
        let Some(kind) = kind else {
            return false;
        };
        let path = self.path(kind);
        match path.conn.lock().unwrap().send_datagram(encoded) {
            Ok(()) => {
                path.transmitted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                tracing::warn!(path = %kind.label(), %e, "datagram send failed; retained for retransmit");
                true // retained in window; will be retransmitted
            }
        }
    }

    /// Process an inbound SACK: retire acked packets and retransmit gaps on a
    /// surviving path.
    fn handle_sack(&self, largest_contiguous: u64, ranges: &[(u64, u64)]) {
        let gaps = self
            .send_window
            .lock()
            .unwrap()
            .ack(largest_contiguous, ranges);
        if gaps.is_empty() {
            return;
        }
        for seq in gaps {
            let packet = self.send_window.lock().unwrap().get(seq);
            if let Some(packet) = packet {
                self.retransmit(seq, packet);
            }
        }
    }

    /// Retransmit a retained packet on the best surviving path.
    fn retransmit(&self, seq: u64, packet: Bytes) {
        let kind = {
            let mut sched = self.scheduler.lock().unwrap();
            for k in PathKind::ALL {
                sched.set_eligible(k, self.is_ready(k) && self.is_alive(k));
            }
            sched.pick()
        };
        let Some(kind) = kind else {
            return;
        };
        let encoded = multipass_proto::encode(&Frame::Data { seq, packet });
        let path = self.path(kind);
        if path.conn.lock().unwrap().send_datagram(encoded).is_ok() {
            path.transmitted.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(seq, path = %kind.label(), "retransmitted packet");
        }
    }

    /// Called when a path dies: retransmit all its unacked packets on the
    /// surviving path so a path failure never strands an only copy.
    pub fn on_path_dead(&self, dead: PathKind) {
        {
            let mut sched = self.scheduler.lock().unwrap();
            sched.set_eligible(dead, false);
        }
        let unacked = self.send_window.lock().unwrap().unacked();
        for seq in unacked {
            let packet = self.send_window.lock().unwrap().get(seq);
            if let Some(packet) = packet {
                self.retransmit(seq, packet);
            }
        }
    }

    /// Send a control frame on one specific live path.
    pub fn send_frame_on(&self, kind: PathKind, frame: &Frame) -> bool {
        if !self.is_alive(kind) {
            return false;
        }
        let p = self.path(kind);
        match p
            .conn
            .lock()
            .unwrap()
            .send_datagram(multipass_proto::encode(frame))
        {
            Ok(()) => {
                p.transmitted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                tracing::warn!(path = %kind.label(), %e, "datagram send failed");
                false
            }
        }
    }

    /// Receive the next deduped data frame. Returns `None` once the transport
    /// is fully closed (both paths dead / dropped).
    pub async fn recv_data(&self) -> Option<Data> {
        loop {
            let d = self.data_rx.lock().await.recv().await?;
            self.recv_scoreboard.lock().unwrap().insert(d.seq);
            if self.dedup.lock().unwrap().insert(d.seq) {
                return Some(d);
            }
        }
    }

    /// Broadcast a SACK describing server→client receive state on every ready
    /// path. Called periodically by the daemon so the server can retire and
    /// retransmit its retention window.
    pub fn broadcast_sack(&self) {
        let sack = self.recv_scoreboard.lock().unwrap().generate_sack();
        let encoded = multipass_proto::encode(&sack);
        for kind in PathKind::ALL {
            if !self.is_alive(kind) {
                continue;
            }
            let _ = self
                .path(kind)
                .conn
                .lock()
                .unwrap()
                .send_datagram(encoded.clone());
        }
    }

    /// Receive the next non-data frame (Hello, Assign, ...) for the daemon's
    /// handshake. Pings are answered internally and never surface here. Sack
    /// frames are consumed internally to drive the aggregation retransmission
    /// window and never surface here.
    pub async fn recv_control(&self) -> Option<(PathKind, Frame)> {
        loop {
            let (path, frame) = self.control_rx.lock().await.recv().await?;
            match frame {
                Frame::Sack {
                    largest_contiguous,
                    ranges,
                } => {
                    self.handle_sack(largest_contiguous, &ranges);
                }
                other => return Some((path, other)),
            }
        }
    }

    /// Wait until one path's reader task dies (read error / connection close),
    /// returning which path. Retransmits that path's unacked packets on the
    /// survivor before returning. The daemon re-dials the dead path.
    pub async fn recv_dead(&self) -> PathKind {
        let kind = self
            .dead_rx
            .lock()
            .await
            .recv()
            .await
            .unwrap_or(PathKind::Wired);
        self.on_path_dead(kind);
        kind
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

    /// Mark a path eligible for replicated data after its Hello was acknowledged.
    pub fn mark_ready(&self, kind: PathKind) {
        self.path(kind).ready.store(true, Ordering::Relaxed);
    }

    /// Whether the path acknowledged the current client epoch.
    pub fn is_ready(&self, kind: PathKind) -> bool {
        self.path(kind).ready.load(Ordering::Relaxed)
    }

    /// Number of packets currently retained in the aggregation send window
    /// (unacknowledged). Exposed for tests and status.
    pub fn send_window_len(&self) -> usize {
        self.send_window.lock().unwrap().len()
    }
    /// Raw noq connection for a path (e.g. to await `closed()` or inspect).
    pub fn connection(&self, kind: PathKind) -> Connection {
        self.path(kind).conn.lock().unwrap().clone()
    }

    /// Verify that a path can carry datagrams of at least `required` bytes.
    ///
    /// The tunnel requires 1289 bytes (MTU 1280 + 9 bytes framing). A path
    /// that cannot carry this is not dual-stack ready and must not be used
    /// for IPv6 traffic.
    pub fn verify_datagram_capacity(&self, kind: PathKind, required: usize) -> bool {
        let conn = self.connection(kind);
        match conn.max_datagram_size() {
            Some(max) => max >= required,
            None => false,
        }
    }

    fn path(&self, kind: PathKind) -> &Arc<Path> {
        match kind {
            PathKind::Wired => &self.wired,
            PathKind::Wifi => &self.wifi,
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.probe_task.abort();
        for path in [&self.wired, &self.wifi] {
            path.conn
                .lock()
                .unwrap()
                .close(0u32.into(), b"transport dropped");
        }
    }
}

/// Spawn a reader task for `path`: decode inbound datagrams, auto-answer
/// Pings, measure RTT from probe Pongs, and distribute Data / control frames to
/// the shared channels. On a read error or connection close it marks the path
/// dead and notifies.
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
    let generation = path.generation.load(Ordering::Acquire);
    let conn = Arc::clone(&path.conn);
    let mark_recv = {
        let p = Arc::clone(&path);
        move || p.mark_recv()
    };
    let set_rtt = {
        let p = Arc::clone(&path);
        move |rtt| p.set_rtt(rtt)
    };
    let probe = Arc::clone(&path.probe);
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
                                .send(Data {
                                    seq,
                                    packet,
                                    path: kind,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Some(Frame::Ping { nonce }) => {
                            let _ =
                                conn.send_datagram(multipass_proto::encode(&Frame::Pong { nonce }));
                        }
                        Some(Frame::Pong { nonce }) => {
                            let mut inflight = probe.lock().unwrap();
                            if let Some((probe_generation, probe_nonce, sent)) = *inflight
                                && probe_generation == generation
                                && probe_nonce == nonce
                            {
                                let rtt = sent.elapsed();
                                *inflight = None;
                                set_rtt(rtt);
                            }
                        }
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
                    if path.mark_dead(generation) {
                        let _ = dead_tx.send(kind).await;
                    }
                    break;
                }
            }
        }
    });
}

/// Spawn a periodic probe task on each live path. Matching Pongs update the
/// per-path RTT exposed through status.
fn spawn_probe(
    wired: &Arc<Path>,
    wifi: &Arc<Path>,
    dead_tx: &mpsc::Sender<PathKind>,
) -> tokio::task::JoinHandle<()> {
    let paths = [Arc::clone(wired), Arc::clone(wifi)];
    let dead_tx = dead_tx.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RTT_PROBE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            for p in &paths {
                if !p.alive.load(Ordering::Acquire) {
                    continue;
                }
                let probe_state = *p.probe.lock().unwrap();
                if let Some((probe_generation, _, sent)) = probe_state {
                    if sent.elapsed() < PROBE_TIMEOUT {
                        continue;
                    }
                    if p.mark_dead(probe_generation) {
                        tracing::warn!(path = %p.kind.label(), "path liveness probe timed out");
                        let _ = dead_tx.send(p.kind).await;
                    }
                    continue;
                }

                let nonce = p.probe_nonce.fetch_add(1, Ordering::Relaxed);
                let datagram = multipass_proto::encode(&Frame::Ping { nonce });
                let sent_generation = {
                    let connection = p.conn.lock().unwrap();
                    let generation = p.generation.load(Ordering::Acquire);
                    connection
                        .send_datagram(datagram)
                        .is_ok()
                        .then_some(generation)
                };
                if let Some(generation) = sent_generation {
                    let mut inflight = p.probe.lock().unwrap();
                    if p.alive.load(Ordering::Acquire)
                        && p.generation.load(Ordering::Acquire) == generation
                    {
                        *inflight = Some((generation, nonce, Instant::now()));
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Echo server: decodes replicated inbound data frames and re-sends each
    /// copy on the connection it arrived on; client dedup exposes one result.
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
                    while let Ok(d) = conn.read_datagram().await {
                        if let Some(Frame::Data { seq, packet }) = multipass_proto::decode(&d) {
                            let _ = conn.send_datagram(multipass_proto::encode(&Frame::Data {
                                seq,
                                packet,
                            }));
                        }
                    }
                });
            }
        });
        addr
    }
    async fn spawn_close_observing_server() -> (SocketAddr, mpsc::Receiver<()>) {
        let server = Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let (closed_tx, closed_rx) = mpsc::channel(2);
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let closed_tx = closed_tx.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let _ = conn.closed().await;
                    let _ = closed_tx.send(()).await;
                });
            }
        });
        (addr, closed_rx)
    }
    async fn spawn_blackhole_proxy(server: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let forwarding = Arc::new(AtomicBool::new(true));
        let task_socket = socket.clone();
        let task_forwarding = forwarding.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            let mut client = None;
            loop {
                let Ok((len, source)) = task_socket.recv_from(&mut buf).await else {
                    break;
                };
                if !task_forwarding.load(Ordering::Relaxed) {
                    continue;
                }
                let destination = if source == server {
                    let Some(client) = client else { continue };
                    client
                } else {
                    client = Some(source);
                    server
                };
                let _ = task_socket.send_to(&buf[..len], destination).await;
            }
        });
        (addr, forwarding)
    }
    async fn spawn_client_to_server_blackhole_proxy(
        server: SocketAddr,
    ) -> (SocketAddr, Arc<AtomicBool>) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let forward_client = Arc::new(AtomicBool::new(true));
        let task_socket = socket.clone();
        let task_forward_client = forward_client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            let mut client = None;
            loop {
                let Ok((len, source)) = task_socket.recv_from(&mut buf).await else {
                    break;
                };
                let destination = if source == server {
                    let Some(client) = client else { continue };
                    client
                } else {
                    client = Some(source);
                    if !task_forward_client.load(Ordering::Relaxed) {
                        continue;
                    }
                    server
                };
                let _ = task_socket.send_to(&buf[..len], destination).await;
            }
        });
        (addr, forward_client)
    }

    #[tokio::test]
    async fn silent_network_blackhole_closes_path_within_failover_bound() {
        let server = Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let Some(incoming) = server.accept().await else {
                return;
            };
            let Ok(conn) = incoming.await else { return };
            let _ = conn.closed().await;
        });
        let (proxy, forwarding) = spawn_blackhole_proxy(server_addr).await;
        let conn = dial(proxy, "127.0.0.1".parse().unwrap(), "blackhole-test")
            .await
            .unwrap();

        forwarding.store(false, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(4), conn.closed())
            .await
            .expect("silent path loss must close QUIC within the failover bound");
    }

    #[tokio::test]
    async fn unanswered_probe_surfaces_path_death_once() {
        let server = Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    while let Ok(datagram) = conn.read_datagram().await {
                        if let Some(Frame::Ping { nonce }) = multipass_proto::decode(&datagram) {
                            let _ =
                                conn.send_datagram(multipass_proto::encode(&Frame::Pong { nonce }));
                        }
                    }
                });
            }
        });
        let (wired_proxy, wired_forwarding) =
            spawn_client_to_server_blackhole_proxy(server_addr).await;
        let wired = dial(wired_proxy, "127.0.0.1".parse().unwrap(), "wired-test")
            .await
            .unwrap();
        let wifi = dial(server_addr, "127.0.0.1".parse().unwrap(), "wifi-test")
            .await
            .unwrap();
        let transport = Transport::from_connections(wired, wifi);

        wired_forwarding.store(false, Ordering::Relaxed);
        let dead = tokio::time::timeout(Duration::from_secs(3), transport.recv_dead())
            .await
            .expect(
                "application probe must detect a silent path before asymmetric QUIC idle timeout",
            );
        assert_eq!(dead, PathKind::Wired);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), transport.recv_dead())
                .await
                .is_err(),
            "one failed path must emit one death notification"
        );
    }

    #[tokio::test]
    async fn dropping_transport_closes_both_connections() {
        let (addr, mut closed_rx) = spawn_close_observing_server().await;
        let transport = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();

        drop(transport);

        tokio::time::timeout(Duration::from_secs(1), async {
            closed_rx.recv().await.unwrap();
            closed_rx.recv().await.unwrap();
        })
        .await
        .expect("both paths must close when their transport is dropped");
    }

    #[tokio::test]
    async fn aggregated_send_stripes_and_delivers_once() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
        for kind in PathKind::ALL {
            t.mark_ready(kind);
        }

        const N: u64 = 20;
        for seq in 0..N {
            assert!(t.send_data(seq, Bytes::from_static(b"hello")));
        }

        let mut got = std::collections::HashSet::new();
        for _ in 0..N {
            let d = t.recv_data().await.unwrap();
            assert_eq!(d.packet, Bytes::from_static(b"hello"));
            got.insert(d.seq);
        }
        assert_eq!(got.len(), N as usize, "dedup delivers each seq once");
        for seq in 0..N {
            assert!(got.contains(&seq), "seq {seq} delivered");
        }

        // Aggregation: total transmitted across both paths is ~N (each packet
        // sent once, on one path), not 2N as in replication. Every packet is
        // retained in the send window for possible retransmission.
        let st = t.status();
        let total_tx = st.wired.transmitted + st.wifi.transmitted;
        assert_eq!(total_tx, N, "each packet striped onto exactly one path");
    }
    #[tokio::test]
    async fn datagram_capacity_supports_tunnel_mtu() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();

        // Required: MTU 1280 + 9 bytes framing = 1289 bytes
        // PMTUD starts at 1200 and climbs; poll until convergence or timeout
        const REQUIRED: usize = 1289;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for kind in PathKind::ALL {
            loop {
                let conn = t.connection(kind);
                let max = conn.max_datagram_size().unwrap_or(0);
                if max >= REQUIRED {
                    break;
                }
                if std::time::Instant::now() > deadline {
                    panic!(
                        "path {} did not reach {REQUIRED}-byte capacity (final: {max})",
                        kind.label(),
                    );
                }
                // Trigger PMTUD by sending traffic
                let _ = t.send_data(1, Bytes::from(vec![0u8; 100]));
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }

    #[tokio::test]
    async fn oversized_data_reports_send_failure() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
        t.mark_ready(PathKind::Wired);

        assert!(!t.send_data(1, Bytes::from(vec![0; 64 * 1024])));
        assert_eq!(
            t.status().wired.transmitted + t.status().wifi.transmitted,
            0
        );
    }

    #[tokio::test]
    async fn path_death_retransmits_unacked_on_survivor() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
        for kind in PathKind::ALL {
            t.mark_ready(kind);
        }

        // Send a few packets; they stripe across paths and stay unacked
        // (the echo server returns them as Data, not Sack, so nothing retires).
        const N: u64 = 6;
        for seq in 0..N {
            assert!(t.send_data(seq, Bytes::from_static(b"data")));
        }
        // Drain the echoes so they don't confuse the later count.
        for _ in 0..N {
            let _ = t.recv_data().await.unwrap();
        }

        // Kill the wired path at the connection level. The reader task marks
        // it dead; recv_dead triggers retransmission of all unacked packets
        // onto the surviving wifi path.
        t.connection(PathKind::Wired)
            .close(0u32.into(), b"test: kill wired");
        let dead = tokio::time::timeout(Duration::from_secs(2), t.recv_dead())
            .await
            .expect("wired death must surface");
        assert_eq!(dead, PathKind::Wired);

        // Every unacked packet must have been retransmitted on wifi, so wifi's
        // transmitted count exceeds what it originally carried.
        let st = t.status();
        assert!(!st.wired.alive);
        // wifi now carries retransmissions of wired's unacked packets in
        // addition to its own original stripes.
        assert!(
            st.wifi.transmitted >= N / 2,
            "survivor must carry retransmitted packets, got {}",
            st.wifi.transmitted
        );
    }
}
