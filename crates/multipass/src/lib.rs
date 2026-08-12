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

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use multipass_proto::{Frame, ReorderBuffer, ReorderInsert};
use noq::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::sync::mpsc;

/// Re-export the wire format so callers don't need a second `use` path.
pub use multipass_proto;
pub use multipass_proto::{PathId, Scheduler, SendWindow, UplinkId};

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
/// Maximum wait for a missing striped packet after later packets arrive.
/// This leaves multiple 10ms SACK cycles for retransmission, then releases
/// the buffered suffix so one lost raw packet cannot wedge the tunnel.
const REORDER_GAP_TIMEOUT: Duration = Duration::from_millis(50);

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
    tc.initial_mtu(1_400);
    tc.min_mtu(1_400);
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

/// Configuration for dialing one logical uplink.
#[derive(Debug, Clone)]
pub struct UplinkDial {
    pub path_id: PathId,
    pub uplink_id: UplinkId,
    pub source: IpAddr,
}

/// One established connection supplied to a transport registry.
pub struct UplinkConnection {
    pub path_id: PathId,
    pub uplink_id: UplinkId,
    pub connection: Connection,
}

/// A single live QUIC connection for one logical uplink.
struct Path {
    path_id: PathId,
    uplink_id: UplinkId,
    conn: Arc<Mutex<Connection>>,
    alive: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    last_recv: Arc<AtomicU64>,
    rtt: Arc<AtomicU64>,
    probe: Arc<Mutex<Option<(u64, u64, Instant)>>>,
    probe_nonce: Arc<AtomicU64>,
    generation: Arc<AtomicU64>,
    started: Instant,
    received: Arc<AtomicU64>,
    transmitted: Arc<AtomicU64>,
    received_bytes: Arc<AtomicU64>,
    transmitted_bytes: Arc<AtomicU64>,
}

impl Path {
    fn new(path_id: PathId, uplink_id: UplinkId, conn: Connection) -> Self {
        Self {
            path_id,
            uplink_id,
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
            received_bytes: Arc::new(AtomicU64::new(0)),
            transmitted_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    fn status(&self) -> UplinkStatus {
        let last_recv = micros_to_instant(self.started, self.last_recv.load(Ordering::Relaxed));
        let rtt = {
            let micros = self.rtt.load(Ordering::Relaxed);
            (micros != 0).then(|| Duration::from_micros(micros))
        };
        UplinkStatus {
            path_id: self.path_id,
            uplink_id: self.uplink_id.clone(),
            alive: self.alive.load(Ordering::Relaxed),
            ready: self.ready.load(Ordering::Relaxed),
            last_recv,
            rtt,
            received: self.received.load(Ordering::Relaxed),
            transmitted: self.transmitted.load(Ordering::Relaxed),
            received_bytes: self.received_bytes.load(Ordering::Relaxed),
            transmitted_bytes: self.transmitted_bytes.load(Ordering::Relaxed),
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
        let connection = self.conn.lock().unwrap();
        if self.generation.load(Ordering::Acquire) != generation
            || self
                .alive
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        self.ready.store(false, Ordering::Release);
        connection.close(0u32.into(), b"path liveness timeout");
        drop(connection);
        *self.probe.lock().unwrap() = None;
        true
    }
}

fn micros_to_instant(started: Instant, micros: u64) -> Option<Instant> {
    (micros != 0).then(|| started + Duration::from_micros(micros))
}

/// Per-uplink liveness and traffic snapshot.
#[derive(Debug, Clone)]
pub struct UplinkStatus {
    pub path_id: PathId,
    pub uplink_id: UplinkId,
    pub alive: bool,
    pub ready: bool,
    pub last_recv: Option<Instant>,
    pub rtt: Option<Duration>,
    pub received: u64,
    pub transmitted: u64,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct TransportStatus {
    pub uplinks: Vec<UplinkStatus>,
}

impl TransportStatus {
    pub fn any_alive(&self) -> bool {
        self.uplinks.iter().any(|uplink| uplink.alive)
    }

    pub fn get(&self, path_id: PathId) -> Option<&UplinkStatus> {
        self.uplinks.iter().find(|uplink| uplink.path_id == path_id)
    }
}

#[derive(Debug, Clone)]
pub struct Data {
    pub seq: u64,
    pub packet: Bytes,
    pub path: PathId,
}

/// Dynamic N-uplink client transport. Reliability state belongs to the logical
/// session; connections and their liveness state belong to registered uplinks.
pub struct Transport {
    paths: Vec<Arc<Path>>,
    path_indices: HashMap<PathId, usize>,
    data_rx: tokio::sync::Mutex<mpsc::Receiver<Data>>,
    control_rx: tokio::sync::Mutex<mpsc::Receiver<(PathId, Frame)>>,
    dead_rx: tokio::sync::Mutex<mpsc::Receiver<PathId>>,
    data_tx: mpsc::Sender<Data>,
    control_tx: mpsc::Sender<(PathId, Frame)>,
    dead_tx: mpsc::Sender<PathId>,
    recv_scoreboard: Mutex<multipass_proto::SackScoreboard>,
    reorder_activity: Mutex<Instant>,
    reorder: Mutex<ReorderBuffer<Data>>,
    probe_task: tokio::task::JoinHandle<()>,
    send_window: Mutex<SendWindow>,
    scheduler: Mutex<Scheduler>,
}

impl Transport {
    pub async fn connect(server: SocketAddr, uplinks: Vec<UplinkDial>) -> Result<Self, TransportError> {
        let mut connections = Vec::with_capacity(uplinks.len());
        for uplink in uplinks {
            let connection = dial(server, uplink.source, uplink.uplink_id.as_str()).await?;
            connections.push(UplinkConnection {
                path_id: uplink.path_id,
                uplink_id: uplink.uplink_id,
                connection,
            });
        }
        Ok(Self::from_connections(connections))
    }

    pub fn from_connections(connections: Vec<UplinkConnection>) -> Self {
        let (data_tx, data_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (dead_tx, dead_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let mut paths = Vec::with_capacity(connections.len());
        let mut path_indices = HashMap::with_capacity(connections.len());
        let mut scheduler = Scheduler::new();

        for uplink in connections {
            assert!(
                !path_indices.contains_key(&uplink.path_id),
                "duplicate path ID {}",
                uplink.path_id.get()
            );
            let index = paths.len();
            path_indices.insert(uplink.path_id, index);
            scheduler.insert(uplink.path_id);
            paths.push(Arc::new(Path::new(
                uplink.path_id,
                uplink.uplink_id,
                uplink.connection,
            )));
        }
        for path in &paths {
            spawn_reader(path, &data_tx, &control_tx, &dead_tx);
        }
        let probe_task = spawn_probe(paths.clone(), &dead_tx);

        Self {
            paths,
            path_indices,
            data_rx: tokio::sync::Mutex::new(data_rx),
            control_rx: tokio::sync::Mutex::new(control_rx),
            dead_rx: tokio::sync::Mutex::new(dead_rx),
            data_tx,
            control_tx,
            dead_tx,
            recv_scoreboard: Mutex::new(multipass_proto::SackScoreboard::new()),
            reorder_activity: Mutex::new(Instant::now()),
            reorder: Mutex::new(ReorderBuffer::new(CHANNEL_CAPACITY)),
            probe_task,
            send_window: Mutex::new(SendWindow::new(CHANNEL_CAPACITY)),
            scheduler: Mutex::new(scheduler),
        }
    }

    pub fn path_ids(&self) -> impl ExactSizeIterator<Item = PathId> + '_ {
        self.paths.iter().map(|path| path.path_id)
    }

    pub fn install_reconnected_path(&self, path_id: PathId, new_conn: Connection) -> bool {
        let Some(path) = self.path(path_id) else {
            return false;
        };
        {
            let mut connection = path.conn.lock().unwrap();
            path.alive.store(false, Ordering::Release);
            path.generation.fetch_add(1, Ordering::AcqRel);
            *connection = new_conn;
            path.ready.store(false, Ordering::Relaxed);
            path.rtt.store(0, Ordering::Relaxed);
            path.alive.store(true, Ordering::Release);
        }
        *path.probe.lock().unwrap() = None;
        spawn_reader(path, &self.data_tx, &self.control_tx, &self.dead_tx);
        tracing::info!(path_id = path_id.get(), uplink = %path.uplink_id, "path reconnected");
        true
    }

    fn refresh_scheduler(&self) {
        let mut scheduler = self.scheduler.lock().unwrap();
        for path in &self.paths {
            scheduler.set_eligible(
                path.path_id,
                path.ready.load(Ordering::Relaxed) && path.alive.load(Ordering::Relaxed),
            );
            let connection = path.conn.lock().unwrap();
            if let Some(stats) = connection.path_stats(noq_proto::PathId::ZERO) {
                scheduler.note_path_stats(path.path_id, stats.rtt, stats.cwnd);
            } else {
                let rtt = path.rtt.load(Ordering::Relaxed);
                if rtt > 0 {
                    scheduler.note_rtt(path.path_id, Duration::from_micros(rtt));
                }
            }
            scheduler.note_queue_space(path.path_id, connection.datagram_send_buffer_space());
        }
    }

    pub fn send_data(&self, seq: u64, packet: Bytes) -> bool {
        let packet_len = packet.len() as u64;
        let encoded = multipass_proto::encode(&Frame::Data {
            seq,
            packet: packet.clone(),
        });
        if !self.paths.iter().any(|path| {
            path.conn
                .lock()
                .unwrap()
                .max_datagram_size()
                .is_some_and(|max| encoded.len() <= max)
        }) {
            return false;
        }

        self.refresh_scheduler();
        let Some(path_id) = self.scheduler.lock().unwrap().pick() else {
            return false;
        };
        self.send_window.lock().unwrap().insert(seq, packet);
        let path = self.path(path_id).expect("scheduler returned registered path");
        match path.conn.lock().unwrap().send_datagram(encoded) {
            Ok(()) => {
                path.transmitted.fetch_add(1, Ordering::Relaxed);
                path.transmitted_bytes.fetch_add(packet_len, Ordering::Relaxed);
                true
            }
            Err(error) => {
                tracing::warn!(path_id = path_id.get(), uplink = %path.uplink_id, %error, "datagram send failed; retained for retransmit");
                true
            }
        }
    }

    fn handle_sack(&self, largest_contiguous: u64, ranges: &[(u64, u64)]) {
        let gaps = self.send_window.lock().unwrap().ack(largest_contiguous, ranges);
        for seq in gaps {
            if let Some(packet) = self.send_window.lock().unwrap().get(seq) {
                self.retransmit(seq, packet);
            }
        }
    }

    fn retransmit(&self, seq: u64, packet: Bytes) {
        self.refresh_scheduler();
        let Some(path_id) = self.scheduler.lock().unwrap().pick() else {
            return;
        };
        let packet_len = packet.len() as u64;
        let encoded = multipass_proto::encode(&Frame::Data { seq, packet });
        let path = self.path(path_id).expect("scheduler returned registered path");
        if path.conn.lock().unwrap().send_datagram(encoded).is_ok() {
            path.transmitted.fetch_add(1, Ordering::Relaxed);
            path.transmitted_bytes.fetch_add(packet_len, Ordering::Relaxed);
            tracing::debug!(seq, path_id = path_id.get(), uplink = %path.uplink_id, "retransmitted packet");
        }
    }

    pub fn on_path_dead(&self, dead: PathId) {
        self.scheduler.lock().unwrap().set_eligible(dead, false);
        let unacked = self.send_window.lock().unwrap().unacked();
        for seq in unacked {
            if let Some(packet) = self.send_window.lock().unwrap().get(seq) {
                self.retransmit(seq, packet);
            }
        }
    }

    pub fn send_frame_on(&self, path_id: PathId, frame: &Frame) -> bool {
        let Some(path) = self.path(path_id) else {
            return false;
        };
        if !path.alive.load(Ordering::Relaxed) {
            return false;
        }
        match path.conn.lock().unwrap().send_datagram(multipass_proto::encode(frame)) {
            Ok(()) => {
                path.transmitted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(error) => {
                tracing::warn!(path_id = path_id.get(), uplink = %path.uplink_id, %error, "datagram send failed");
                false
            }
        }
    }

    pub async fn recv_data(&self) -> Option<Data> {
        loop {
            if let Some(ready) = self.reorder.lock().unwrap().pop_ready() {
                return Some(ready);
            }
            let gap_deadline = self
                .reorder
                .lock()
                .unwrap()
                .has_gap()
                .then(|| *self.reorder_activity.lock().unwrap() + REORDER_GAP_TIMEOUT);
            let mut data_rx = self.data_rx.lock().await;
            let data = if let Some(deadline) = gap_deadline {
                tokio::select! {
                    data = data_rx.recv() => data?,
                    _ = tokio::time::sleep_until(deadline.into()) => {
                        drop(data_rx);
                        let mut reorder = self.reorder.lock().unwrap();
                        if let Some((first, last)) = reorder.skip_missing_prefix() {
                            tracing::debug!(first, last, next_seq = reorder.next_seq(), occupancy = reorder.occupancy(), span = ?reorder.buffered_span(), "reorder gap timed out; releasing buffered suffix");
                            self.recv_scoreboard.lock().unwrap().abandon_through(last);
                        }
                        continue;
                    }
                }
            } else {
                data_rx.recv().await?
            };
            drop(data_rx);
            let seq = data.seq;
            *self.reorder_activity.lock().unwrap() = Instant::now();
            let mut reorder = self.reorder.lock().unwrap();
            match reorder.insert(seq, data) {
                ReorderInsert::Rejected => continue,
                ReorderInsert::Admitted => {
                    self.recv_scoreboard.lock().unwrap().insert(seq);
                }
                ReorderInsert::AdmittedAfterSkipping { last, .. } => {
                    let mut scoreboard = self.recv_scoreboard.lock().unwrap();
                    scoreboard.abandon_through(last);
                    scoreboard.insert(seq);
                }
            }
        }
    }

    pub fn broadcast_sack(&self) {
        let encoded = multipass_proto::encode(&self.recv_scoreboard.lock().unwrap().generate_sack());
        for path in &self.paths {
            if path.alive.load(Ordering::Relaxed) {
                let _ = path.conn.lock().unwrap().send_datagram(encoded.clone());
            }
        }
    }

    pub async fn recv_control(&self) -> Option<(PathId, Frame)> {
        loop {
            let (path, frame) = self.control_rx.lock().await.recv().await?;
            match frame {
                Frame::Sack {
                    largest_contiguous,
                    ranges,
                } => self.handle_sack(largest_contiguous, &ranges),
                other => return Some((path, other)),
            }
        }
    }

    pub async fn recv_dead(&self) -> PathId {
        let path_id = self
            .dead_rx
            .lock()
            .await
            .recv()
            .await
            .expect("transport retains dead sender while alive");
        self.on_path_dead(path_id);
        path_id
    }

    pub fn status(&self) -> TransportStatus {
        TransportStatus {
            uplinks: self.paths.iter().map(|path| path.status()).collect(),
        }
    }

    pub fn path_status(&self, path_id: PathId) -> Option<UplinkStatus> {
        self.path(path_id).map(|path| path.status())
    }

    pub fn is_alive(&self, path_id: PathId) -> bool {
        self.path(path_id)
            .is_some_and(|path| path.alive.load(Ordering::Relaxed))
    }

    pub fn mark_ready(&self, path_id: PathId) -> bool {
        let Some(path) = self.path(path_id) else {
            return false;
        };
        path.ready.store(true, Ordering::Relaxed);
        true
    }

    pub fn is_ready(&self, path_id: PathId) -> bool {
        self.path(path_id)
            .is_some_and(|path| path.ready.load(Ordering::Relaxed))
    }

    pub fn send_window_len(&self) -> usize {
        self.send_window.lock().unwrap().len()
    }

    pub fn connection(&self, path_id: PathId) -> Option<Connection> {
        self.path(path_id)
            .map(|path| path.conn.lock().unwrap().clone())
    }

    pub fn verify_datagram_capacity(&self, path_id: PathId, required: usize) -> bool {
        self.connection(path_id)
            .and_then(|connection| connection.max_datagram_size())
            .is_some_and(|max| max >= required)
    }

    fn path(&self, path_id: PathId) -> Option<&Arc<Path>> {
        self.path_indices.get(&path_id).map(|index| &self.paths[*index])
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.probe_task.abort();
        for path in &self.paths {
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
    control_tx: &mpsc::Sender<(PathId, Frame)>,
    dead_tx: &mpsc::Sender<PathId>,
) {
    let path = Arc::clone(path);
    let path_id = path.path_id;
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
                            path.received_bytes
                                .fetch_add(packet.len() as u64, Ordering::Relaxed);
                            if data_tx
                                .send(Data {
                                    seq,
                                    packet,
                                    path: path_id,
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
                            if control_tx.send((path_id, other)).await.is_err() {
                                break;
                            }
                        }
                        None => {
                            // Malformed datagram; drop it.
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(path_id = path_id.get(), uplink = %path.uplink_id, %e, "path read ended");
                    if path.mark_dead(generation) {
                        let _ = dead_tx.send(path_id).await;
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
    paths: Vec<Arc<Path>>,
    dead_tx: &mpsc::Sender<PathId>,
) -> tokio::task::JoinHandle<()> {
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
                        tracing::warn!(path_id = p.path_id.get(), uplink = %p.uplink_id, "path liveness probe timed out");
                        let _ = dead_tx.send(p.path_id).await;
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

    fn path(value: u16) -> PathId {
        PathId::new(value)
    }

    fn test_connection(
        path_id: u16,
        uplink_id: &str,
        connection: Connection,
    ) -> UplinkConnection {
        UplinkConnection {
            path_id: path(path_id),
            uplink_id: UplinkId::new(uplink_id).unwrap(),
            connection,
        }
    }

    fn test_dials(count: u16) -> Vec<UplinkDial> {
        (1..=count)
            .map(|id| UplinkDial {
                path_id: path(id),
                uplink_id: UplinkId::new(format!("path-{id}")).unwrap(),
                source: "127.0.0.1".parse().unwrap(),
            })
            .collect()
    }

    fn mark_all_ready(transport: &Transport) {
        for path_id in transport.path_ids() {
            assert!(transport.mark_ready(path_id));
        }
    }

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
        let transport = Transport::from_connections(vec![test_connection(1, "wired", wired), test_connection(2, "wifi", wifi)]);

        wired_forwarding.store(false, Ordering::Relaxed);
        let dead = tokio::time::timeout(Duration::from_secs(3), transport.recv_dead())
            .await
            .expect(
                "application probe must detect a silent path before asymmetric QUIC idle timeout",
            );
        assert_eq!(dead, path(1));
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
        let transport = Transport::connect(addr, test_dials(2))
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
    async fn recv_data_reorders_striped_arrivals_before_delivery() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(addr, test_dials(2))
        .await
        .unwrap();
        mark_all_ready(&t);

        for data in [
            Data {
                seq: 3,
                packet: Bytes::from_static(b"three"),
                path: path(2),
            },
            Data {
                seq: 1,
                packet: Bytes::from_static(b"one"),
                path: path(1),
            },
            Data {
                seq: 2,
                packet: Bytes::from_static(b"two"),
                path: path(1),
            },
        ] {
            t.data_tx.send(data).await.unwrap();
        }

        assert_eq!(t.recv_data().await.unwrap().seq, 1);
        assert_eq!(t.recv_data().await.unwrap().seq, 2);
        assert_eq!(t.recv_data().await.unwrap().seq, 3);
    }

    #[tokio::test]
    async fn recv_data_releases_suffix_after_gap_timeout_without_new_arrivals() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(addr, test_dials(2))
        .await
        .unwrap();
        mark_all_ready(&t);

        for data in [
            Data {
                seq: 2,
                packet: Bytes::from_static(b"two"),
                path: path(1),
            },
            Data {
                seq: 3,
                packet: Bytes::from_static(b"three"),
                path: path(2),
            },
        ] {
            t.data_tx.send(data).await.unwrap();
        }

        let started = Instant::now();
        let packet = tokio::time::timeout(Duration::from_millis(200), t.recv_data())
            .await
            .expect("gap timer must fire without another arrival")
            .unwrap();
        assert_eq!(packet.seq, 2);
        assert!(started.elapsed() >= REORDER_GAP_TIMEOUT);
    }

    #[tokio::test]
    async fn aggregated_send_stripes_and_delivers_once() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(addr, test_dials(2))
        .await
        .unwrap();
        mark_all_ready(&t);

        const N: u64 = 20;
        for seq in 1..=N {
            assert!(t.send_data(seq, Bytes::from_static(b"hello")));
        }

        let mut got = std::collections::HashSet::new();
        for _ in 0..N {
            let d = t.recv_data().await.unwrap();
            assert_eq!(d.packet, Bytes::from_static(b"hello"));
            got.insert(d.seq);
        }
        assert_eq!(got.len(), N as usize, "dedup delivers each seq once");
        for seq in 1..=N {
            assert!(got.contains(&seq), "seq {seq} delivered");
        }

        // Aggregation: total transmitted across both paths is ~N (each packet
        // sent once, on one path), not 2N as in replication. Every packet is
        // retained in the send window for possible retransmission.
        let st = t.status();
        let total_tx_bytes: u64 = st.uplinks.iter().map(|uplink| uplink.transmitted_bytes).sum();
        let total_rx_bytes: u64 = st.uplinks.iter().map(|uplink| uplink.received_bytes).sum();
        assert_eq!(
            total_tx_bytes,
            N * 5,
            "path counters track sent payload bytes"
        );
        assert_eq!(
            total_rx_bytes,
            N * 5,
            "path counters track received payload bytes"
        );
        let total_tx: u64 = st.uplinks.iter().map(|uplink| uplink.transmitted).sum();
        assert_eq!(total_tx, N, "each packet striped onto exactly one path");
    }
    #[tokio::test]
    async fn datagram_capacity_supports_tunnel_mtu() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(addr, test_dials(2))
        .await
        .unwrap();

        const REQUIRED: usize = multipass_proto::TUNNEL_MTU as usize + 9;
        for path_id in t.path_ids() {
            let max = t
                .connection(path_id)
                .unwrap()
                .max_datagram_size()
                .unwrap_or(0);
            assert!(
                max >= REQUIRED,
                "path {} starts with {max}-byte datagram capacity, need {REQUIRED}",
                path_id.get(),
            );
        }
    }

    #[tokio::test]
    async fn oversized_data_reports_send_failure() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(addr, test_dials(2))
        .await
        .unwrap();
        t.mark_ready(path(1));

        assert!(!t.send_data(1, Bytes::from(vec![0; 64 * 1024])));
        assert_eq!(
            t.status()
                .uplinks
                .iter()
                .map(|uplink| uplink.transmitted)
                .sum::<u64>(),
            0
        );
    }

    #[tokio::test]
    async fn path_death_retransmits_unacked_on_survivor() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(addr, test_dials(2))
        .await
        .unwrap();
        mark_all_ready(&t);

        // Send a few packets; they stripe across paths and stay unacked
        // (the echo server returns them as Data, not Sack, so nothing retires).
        const N: u64 = 6;
        for seq in 1..=N {
            assert!(t.send_data(seq, Bytes::from_static(b"data")));
        }
        // Drain the echoes so they don't confuse the later count.
        for _ in 0..N {
            let _ = t.recv_data().await.unwrap();
        }

        // Kill the wired path at the connection level. The reader task marks
        // it dead; recv_dead triggers retransmission of all unacked packets
        // onto the surviving wifi path.
        t.connection(path(1)).unwrap().close(0u32.into(), b"test: kill wired");
        let dead = tokio::time::timeout(Duration::from_secs(2), t.recv_dead())
            .await
            .expect("wired death must surface");
        assert_eq!(dead, path(1));

        // Every unacked packet must have been retransmitted on wifi, so wifi's
        // transmitted count exceeds what it originally carried.
        let st = t.status();
        assert!(!st.get(path(1)).unwrap().alive);
        let survivor = st.get(path(2)).unwrap();
        assert!(
            survivor.transmitted >= N / 2,
            "survivor must carry retransmitted packets, got {}",
            survivor.transmitted
        );
    }
}
