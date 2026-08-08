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
//! # Send policy: aggregate, weighted by live health
//!
//! Each payload datagram is sent on ONE connection, chosen by the
//! [`Scheduler`] (deficit-WRR weighted by live RTT and receive liveness), not
//! duplicated on both. When a path's RTT spikes or its acks stall, its weight
//! shifts onto the survivor so failover stays seamless. The receiver still
//! dedups by sequence number ([`multipass_proto::Dedup`]) — that absorbs the
//! reorder and the brief duplicates that occur while weights re-home.
//!
//! This crate is purely I/O: no TUN, no routing, no platform-specific code. It
//! is macOS + Linux agnostic. The client daemon owns the tunnel device and the
//! Hello/Assign handshake; it drives them through [`Transport::send_frame`] and
//! [`Transport::recv_control`].

mod scheduler;

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

pub use scheduler::{PathHealth, Scheduler, SchedulerConfig};

/// Re-export the wire format so callers don't need a second `use` path.
pub use multipass_proto;

/// ALPN for the multipass tunnel (from multipass-proto).
pub const ALPN: &[u8] = multipass_proto::ALPN;
/// TLS server name (SNI) used when dialing. The self-signed cert is generated
/// for this name; the client verifier skips validation anyway.
pub const SERVER_NAME: &str = "multipass";

/// How often the transport sends a Ping probe on each live path to measure RTT
/// and re-evaluate scheduler stall detection.
pub const RTT_PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// A probe with no Pong reply after this long is considered lost.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
/// liveness/RTT bookkeeping. The connection is swappable so a dead path can be
/// re-dialed in place without tearing down the [`Transport`].
struct Path {
    kind: PathKind,
    conn: Arc<Mutex<Connection>>,
    /// Set false when the reader task hits an error / the conn closes.
    alive: Arc<AtomicBool>,
    /// Microseconds since `started` of the last datagram received (0 = none).
    last_recv: Arc<AtomicU64>,
    /// Last measured RTT in microseconds (0 = none).
    rtt: Arc<AtomicU64>,
    /// In-flight Ping probe: (nonce, sent-at), if any.
    probe: Arc<Mutex<Option<(u64, Instant)>>>,
    /// Monotonic nonce source for Ping probes.
    probe_nonce: Arc<AtomicU64>,
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
            rtt: Arc::new(AtomicU64::new(0)),
            probe: Arc::new(Mutex::new(None)),
            probe_nonce: Arc::new(AtomicU64::new(0)),
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
/// channels, plus a probe loop that measures RTT into the [`Scheduler`].
/// Outbound frames are routed through the scheduler onto ONE path (aggregate,
/// weighted by live health). Sequence dedup is owned here via
/// [`multipass_proto::Dedup`].
pub struct Transport {
    wired: Arc<Path>,
    wifi: Arc<Path>,
    scheduler: Arc<Mutex<Scheduler>>,
    // Receivers are mutex-guarded so `recv_*` can take `&self` and be selected
    // over alongside `send_data`/`send_frame` in one tokio::select!.
    data_rx: tokio::sync::Mutex<mpsc::Receiver<Data>>,
    control_rx: tokio::sync::Mutex<mpsc::Receiver<(PathKind, Frame)>>,
    dead_rx: tokio::sync::Mutex<mpsc::Receiver<PathKind>>,
    // Sender clones kept so a re-dialed path can respawn its reader task.
    data_tx: mpsc::Sender<Data>,
    control_tx: mpsc::Sender<(PathKind, Frame)>,
    dead_tx: mpsc::Sender<PathKind>,
    dedup: Mutex<Dedup>,
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
        let scheduler = Arc::new(Mutex::new(Scheduler::new(SchedulerConfig::default())));

        let (data_tx, data_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (dead_tx, dead_rx) = mpsc::channel(CHANNEL_CAPACITY);

        for p in [&wired, &wifi] {
            spawn_reader(p, &data_tx, &control_tx, &dead_tx, &scheduler);
        }
        spawn_probe(&wired, &wifi, &scheduler);

        Self {
            wired,
            wifi,
            scheduler,
            data_rx: tokio::sync::Mutex::new(data_rx),
            control_rx: tokio::sync::Mutex::new(control_rx),
            dead_rx: tokio::sync::Mutex::new(dead_rx),
            data_tx,
            control_tx,
            dead_tx,
            dedup: Mutex::new(Dedup::new()),
        }
    }

    /// Re-dial one dead path and swap it in, respawning its reader task and
    /// restoring it in the scheduler. The daemon calls this on
    /// [`Transport::recv_dead`]. Returns the dial error if the interface is
    /// still down; callers retry with backoff.
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
        p.rtt.store(0, Ordering::Relaxed);
        *p.probe.lock().unwrap() = None;
        self.scheduler.lock().unwrap().set_alive(kind, true);
        spawn_reader(
            p,
            &self.data_tx,
            &self.control_tx,
            &self.dead_tx,
            &self.scheduler,
        );
        tracing::info!(path = %kind.label(), "path reconnected");
        Ok(())
    }

    /// Send a raw IP packet as a data frame on the scheduler-chosen path.
    /// Returns true only when noq accepts the datagram for transmission.
    pub fn send_data(&self, seq: u64, packet: Bytes) -> bool {
        self.send_frame(&Frame::Data { seq, packet })
    }

    /// Send a frame on the scheduler-chosen path. Used for data and control
    /// (Hello, Ping, ...). If the chosen path just died, re-homes to the
    /// survivor; returns false if nothing is alive or noq rejects the datagram.
    pub fn send_frame(&self, frame: &Frame) -> bool {
        let d = multipass_proto::encode(frame);
        let kind = self.scheduler.lock().unwrap().pick();
        let p = if self.is_alive(kind) {
            self.path(kind)
        } else {
            let other = if kind == PathKind::Wired {
                PathKind::Wifi
            } else {
                PathKind::Wired
            };
            if !self.is_alive(other) {
                return false;
            }
            self.path(other)
        };
        match p.conn.lock().unwrap().send_datagram(d) {
            Ok(()) => {
                p.transmitted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                tracing::warn!(path = %p.kind.label(), %e, "datagram send failed");
                false
            }
        }
    }

    /// Receive the next deduped data frame. Returns `None` once the transport
    /// is fully closed (both paths dead / dropped).
    pub async fn recv_data(&self) -> Option<Data> {
        loop {
            let d = self.data_rx.lock().await.recv().await?;
            if self.dedup.lock().unwrap().insert(d.seq) {
                return Some(d);
            }
        }
    }

    /// Receive the next non-data frame (Hello, Assign, ...) for the daemon's
    /// handshake. Pings are answered internally and never surface here.
    pub async fn recv_control(&self) -> Option<(PathKind, Frame)> {
        self.control_rx.lock().await.recv().await
    }

    /// Wait until one path's reader task dies (read error / connection close),
    /// returning which path. The daemon re-dials that path.
    pub async fn recv_dead(&self) -> PathKind {
        self.dead_rx
            .lock()
            .await
            .recv()
            .await
            .unwrap_or(PathKind::Wired)
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

    /// Handle to the scheduler, for status/tuning (e.g. `set_weight`).
    pub fn scheduler(&self) -> Arc<Mutex<Scheduler>> {
        Arc::clone(&self.scheduler)
    }

    fn path(&self, kind: PathKind) -> &Arc<Path> {
        match kind {
            PathKind::Wired => &self.wired,
            PathKind::Wifi => &self.wifi,
        }
    }
}

/// Spawn a reader task for `path`: decode inbound datagrams, auto-answer
/// Pings, measure RTT from probe Pongs, feed the scheduler, and distribute
/// Data / control frames to the shared channels. On a read error or connection
/// close it marks the path dead and notifies.
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
    scheduler: &Arc<Mutex<Scheduler>>,
) {
    let path = Arc::clone(path);
    let kind = path.kind;
    let conn = Arc::clone(&path.conn);
    let alive = Arc::clone(&path.alive);
    let mark_recv = {
        let p = Arc::clone(&path);
        move || p.mark_recv()
    };
    let set_rtt = {
        let p = Arc::clone(&path);
        move |rtt| p.set_rtt(rtt)
    };
    let probe = Arc::clone(&path.probe);
    let scheduler = Arc::clone(scheduler);
    let data_tx = data_tx.clone();
    let control_tx = control_tx.clone();
    let dead_tx = dead_tx.clone();

    tokio::spawn(async move {
        loop {
            let conn = conn.lock().unwrap().clone();
            match conn.read_datagram().await {
                Ok(d) => {
                    mark_recv();
                    scheduler.lock().unwrap().note_recv(kind);
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
                            // RTT from the matching in-flight probe, if any.
                            let mut inflight = probe.lock().unwrap();
                            if let Some((n, sent)) = *inflight
                                && n == nonce
                            {
                                let rtt = sent.elapsed();
                                *inflight = None;
                                set_rtt(rtt);
                                scheduler.lock().unwrap().note_rtt(kind, rtt);
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
                    alive.store(false, Ordering::Relaxed);
                    scheduler.lock().unwrap().set_alive(kind, false);
                    let _ = dead_tx.send(kind).await;
                    break;
                }
            }
        }
    });
}

/// Spawn a periodic probe task: re-evaluate the scheduler's stall state and, on
/// each live path, send a Ping probe and arm the RTT measurement. The matching
/// Pong (handled by the reader) yields the RTT that feeds the scheduler.
fn spawn_probe(wired: &Arc<Path>, wifi: &Arc<Path>, scheduler: &Arc<Mutex<Scheduler>>) {
    let paths = [Arc::clone(wired), Arc::clone(wifi)];
    let scheduler = Arc::clone(scheduler);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RTT_PROBE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            scheduler.lock().unwrap().tick();
            for p in &paths {
                if !p.alive.load(Ordering::Relaxed) {
                    continue;
                }
                // Skip if a probe is still in flight (not yet timed out).
                let mut inflight = p.probe.lock().unwrap();
                if let Some((_, sent)) = *inflight
                    && sent.elapsed() < PROBE_TIMEOUT
                {
                    continue;
                }
                let nonce = p.probe_nonce.fetch_add(1, Ordering::Relaxed);
                let d = multipass_proto::encode(&Frame::Ping { nonce });
                if p.conn.lock().unwrap().send_datagram(d).is_ok() {
                    *inflight = Some((nonce, Instant::now()));
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Echo server: decodes inbound data frames and re-sends them (same seq)
    /// on the connection they arrived on, so the client sees the aggregate
    /// scheduler's choice reflected back on the same path.
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
                                    let _ =
                                        conn.send_datagram(multipass_proto::encode(&Frame::Data {
                                            seq,
                                            packet,
                                        }));
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
    async fn aggregate_scheduler_delivers_all_and_spreads() {
        let addr = spawn_echo_server().await;
        // Both paths bound to loopback (distinct ephemeral source ports).
        let t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();

        const N: u64 = 20;
        for seq in 0..N {
            t.send_data(seq, Bytes::from_static(b"hello"));
        }

        // Every seq is delivered exactly once (the scheduler routes each packet
        // to one path; the echo reflects it back on that path). Delivery order
        // is not guaranteed across the two paths' differing RTTs — check the set.
        let mut got = std::collections::HashSet::new();
        for _ in 0..N {
            let d = t.recv_data().await.unwrap();
            assert_eq!(d.packet, Bytes::from_static(b"hello"));
            got.insert(d.seq);
        }
        assert_eq!(got.len(), N as usize, "each seq delivered exactly once");
        for seq in 0..N {
            assert!(got.contains(&seq), "seq {seq} delivered");
        }

        // Both paths alive, and the aggregate scheduler spread load across both
        // (equal weights -> both transmit and receive).
        let st = t.status();
        assert!(st.wired.alive, "wired path should be alive");
        assert!(st.wifi.alive, "wifi path should be alive");
        assert!(st.wired.transmitted > 0, "scheduler must use wired");
        assert!(st.wifi.transmitted > 0, "scheduler must use wifi");
        assert!(st.wired.received > 0 && st.wifi.received > 0);
    }
    #[tokio::test]
    async fn tunnel_mtu_packet_fits_quic_datagram() {
        let addr = spawn_echo_server().await;
        let t = Transport::connect(
            addr,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();

        let frame = multipass_proto::encode(&Frame::Data {
            seq: 1,
            packet: Bytes::from(vec![0; multipass_proto::TUNNEL_MTU as usize]),
        });
        for kind in PathKind::ALL {
            let maximum = t.connection(kind).max_datagram_size().unwrap();
            assert!(
                frame.len() <= maximum,
                "{}-byte tunnel frame exceeds {} path's {maximum}-byte QUIC datagram limit",
                frame.len(),
                kind.label(),
            );
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

        assert!(!t.send_data(1, Bytes::from(vec![0; 64 * 1024])));
        assert_eq!(
            t.status().wired.transmitted + t.status().wifi.transmitted,
            0
        );
    }
}
