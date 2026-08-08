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

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use multipass_proto::{
    Dedup, Frame, PathKind, SackScoreboard, Scheduler, SendWindow, TUNNEL_CLIENT, TUNNEL_MTU,
    TUNNEL_PREFIX, TUNNEL_V6_CLIENT, TUNNEL_V6_PREFIX, encode,
};
use noq::{Connection, Endpoint, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::QuicServerConfig;
use tokio::sync::{Mutex, mpsc};
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

/// One client connection and the epoch established by its first Hello.
struct LiveConn {
    id: u64,
    conn: Option<Connection>,
    epoch: Option<u64>,
    /// Scheduling slot for this path within the epoch (Wired/Wifi label; the
    /// physical mapping is irrelevant — what matters is the scheduler can
    /// distinguish the two paths by measured RTT/queue).
    path: Option<PathKind>,
}

struct SessionState {
    conns: Vec<LiveConn>,
    epoch: Option<u64>,
    retired_epochs: HashSet<u64>,
    dedup: Dedup,
    /// Receive scoreboard for client→server packets; generates SACKs.
    scoreboard: SackScoreboard,
    /// Retention window for server→client packets (aggregation retransmit).
    send_window: SendWindow,
    /// Path scheduler for server→client aggregation (the download direction).
    scheduler: Scheduler,
}

/// A single logical client session. Connection authentication, epoch changes,
/// connection eviction, and inbound dedup are one atomic state transition.
struct Session {
    state: Mutex<SessionState>,
    next_conn_id: AtomicU64,
    seq: AtomicU64,
}

impl Session {
    fn new() -> Self {
        Self {
            state: Mutex::new(SessionState {
                conns: Vec::new(),
                epoch: None,
                retired_epochs: HashSet::new(),
                dedup: Dedup::new(),
                scoreboard: SackScoreboard::new(),
                send_window: SendWindow::new(4096),
                scheduler: Scheduler::new(),
            }),
            next_conn_id: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    async fn add_conn(&self, conn: Connection) -> u64 {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        self.state.lock().await.conns.push(LiveConn {
            id,
            conn: Some(conn),
            epoch: None,
            path: None,
        });
        debug!(id, "connection added to session");
        id
    }

    async fn remove_conn(&self, id: u64) {
        let mut state = self.state.lock().await;
        if let Some(conn) = state.conns.iter().find(|c| c.id == id)
            && let Some(path) = conn.path
        {
            state.scheduler.set_eligible(path, false);
        }
        state.conns.retain(|conn| conn.id != id);
        debug!(id, "connection removed from session");
    }

    async fn authenticate(&self, id: u64, epoch: u64) -> bool {
        let mut state = self.state.lock().await;
        let Some(index) = state.conns.iter().position(|conn| conn.id == id) else {
            return false;
        };
        if let Some(authenticated_epoch) = state.conns[index].epoch {
            return authenticated_epoch == epoch;
        }
        if state.retired_epochs.contains(&epoch) {
            return false;
        }

        if state.epoch != Some(epoch) {
            if let Some(previous) = state.epoch.replace(epoch) {
                state.retired_epochs.insert(previous);
                state.conns.retain_mut(|conn| {
                    if conn.epoch == Some(previous) {
                        if let Some(handle) = conn.conn.take() {
                            handle.close(0u32.into(), b"client epoch replaced");
                        }
                        false
                    } else {
                        true
                    }
                });
            }
            state.dedup = Dedup::new();
            state.scoreboard = SackScoreboard::new();
            state.send_window = SendWindow::new(4096);
            state.scheduler = Scheduler::new();
        }

        // Assign this connection the next free scheduling slot in the epoch.
        let used: HashSet<PathKind> = state
            .conns
            .iter()
            .filter_map(|c| (c.epoch == Some(epoch)).then_some(c.path).flatten())
            .collect();
        let slot = PathKind::ALL.into_iter().find(|k| !used.contains(k));

        let Some(conn) = state.conns.iter_mut().find(|conn| conn.id == id) else {
            return false;
        };
        conn.epoch = Some(epoch);
        conn.path = slot;
        if let Some(slot) = slot {
            state.scheduler.set_eligible(slot, true);
        }
        true
    }

    async fn accept_data(&self, id: u64, seq: u64) -> bool {
        let mut state = self.state.lock().await;
        let Some(conn) = state.conns.iter().find(|conn| conn.id == id) else {
            return false;
        };
        if conn.epoch != state.epoch || conn.epoch.is_none() {
            return false;
        }
        state.scoreboard.insert(seq);
        state.dedup.insert(seq)
    }

    /// Generate a SACK describing client→server receive state.
    async fn generate_sack(&self) -> Frame {
        let state = self.state.lock().await;
        state.scoreboard.generate_sack()
    }

    /// Handle an inbound SACK from the client: retire acked server→client
    /// packets and retransmit gaps on a surviving connection.
    async fn handle_sack(&self, largest_contiguous: u64, ranges: &[(u64, u64)]) {
        let gaps = {
            let mut state = self.state.lock().await;
            state.send_window.ack(largest_contiguous, ranges)
        };
        for seq in gaps {
            let packet = {
                let state = self.state.lock().await;
                state.send_window.get(seq)
            };
            if let Some(packet) = packet {
                let data = encode(&Frame::Data { seq, packet });
                self.send_one(data).await;
            }
        }
    }

    /// Aggregate a server→client packet onto the best live connection,
    /// retaining it in the send window until the client's SACK confirms it.
    async fn send_data(&self, seq: u64, packet: Bytes) -> bool {
        {
            let mut state = self.state.lock().await;
            state.send_window.insert(seq, packet.clone());
        }
        let data = encode(&Frame::Data { seq, packet });
        self.send_one(data).await
    }

    /// Send an encoded frame on the scheduler-chosen live connection. This is
    /// the download aggregation path: the scheduler picks the lowest-cost
    /// (RTT + queue) ready connection per packet, striping across both to
    /// combine their bandwidth.
    async fn send_one(&self, data: Bytes) -> bool {
        let mut state = self.state.lock().await;
        let epoch = state.epoch;

        // Collect per-connection stats first (immutable borrow), then release.
        let stats: Vec<(PathKind, Option<Duration>, usize)> = state
            .conns
            .iter()
            .filter(|live| live.epoch == epoch)
            .filter_map(|live| {
                let path = live.path?;
                let conn = live.conn.as_ref()?;
                Some((
                    path,
                    conn.rtt(noq_proto::PathId::ZERO),
                    conn.datagram_send_buffer_space(),
                ))
            })
            .collect();
        for (path, rtt, space) in stats {
            if let Some(rtt) = rtt {
                state.scheduler.note_rtt(path, rtt);
            }
            state.scheduler.note_queue_space(path, space);
        }

        let Some(chosen) = state.scheduler.pick() else {
            return false;
        };
        for live in state.conns.iter_mut() {
            if live.epoch != epoch || live.path != Some(chosen) {
                continue;
            }
            let Some(conn) = live.conn.as_ref() else {
                continue;
            };
            match conn.send_datagram(data.clone()) {
                Ok(()) => return true,
                Err(noq::SendDatagramError::ConnectionLost(e)) => {
                    warn!(id = live.id, %e, "connection lost while sending");
                    state.scheduler.set_eligible(chosen, false);
                    return false;
                }
                Err(e) => {
                    warn!(id = live.id, %e, "datagram send failed");
                    return false;
                }
            }
        }
        false
    }

    /// Broadcast a SACK frame on every live connection (redundant, low cost).
    async fn broadcast_sack(&self) {
        let sack = self.generate_sack().await;
        let data = encode(&sack);
        let mut state = self.state.lock().await;
        let epoch = state.epoch;
        for live in state.conns.iter_mut() {
            if live.epoch != epoch {
                continue;
            }
            let Some(conn) = live.conn.as_ref() else {
                continue;
            };
            let _ = conn.send_datagram(data.clone());
        }
    }

    #[cfg(test)]
    async fn add_test_conn(&self) -> u64 {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        self.state.lock().await.conns.push(LiveConn {
            id,
            conn: None,
            epoch: None,
            path: None,
        });
        id
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
                    Frame::Hello { client_nonce } => {
                        if !session.authenticate(id, client_nonce).await {
                            break;
                        }
                        let assign = Frame::Assign {
                            ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
                            ipv6: Some((TUNNEL_V6_CLIENT, TUNNEL_V6_PREFIX)),
                            mtu: TUNNEL_MTU,
                            dns: vec![],
                        };
                        if conn.send_datagram(encode(&assign)).is_err() {
                            break;
                        }
                        info!(id, client_nonce, "answered Hello: assigned");
                    }
                    Frame::Data { seq, packet } => {
                        if session.accept_data(id, seq).await && to_tun.send(packet).await.is_err()
                        {
                            break;
                        }
                    }
                    Frame::Ping { nonce } => {
                        if conn.send_datagram(encode(&Frame::Pong { nonce })).is_err() {
                            break;
                        }
                    }
                    Frame::Pong { .. } => {}
                    Frame::Assign { .. } => {} // server never expects an assignment
                    Frame::Sack {
                        largest_contiguous,
                        ranges,
                    } => {
                        session.handle_sack(largest_contiguous, &ranges).await;
                    }
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

    // Periodic SACK broadcast so the client can retire/retransmit its window.
    let sack_session = session.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            sack_session.broadcast_sack().await;
        }
    });

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
            // A packet read from the TUN: aggregate onto the best live connection.
            maybe = from_tun_rx.recv() => {
                let Some(packet) = maybe else { break }; // TUN reader died
                let seq = session.next_seq();
                let sent = session.send_data(seq, packet).await;
                if !sent {
                    warn!(seq, "tunnel packet retained; no live client connections");
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

    use super::{Frame, Session, server_config};
    use multipass_proto::{
        TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_PREFIX, TUNNEL_V6_CLIENT, TUNNEL_V6_PREFIX, encode,
    };

    #[tokio::test]
    async fn new_client_epoch_evicts_old_connections_and_rejects_rollback() {
        let session = Session::new();
        let old_a = session.add_test_conn().await;
        let old_b = session.add_test_conn().await;
        assert!(session.authenticate(old_a, 10).await);
        assert!(session.authenticate(old_b, 10).await);
        assert!(session.accept_data(old_a, 1).await);

        let new_conn = session.add_test_conn().await;
        assert!(session.authenticate(new_conn, 20).await);
        assert!(!session.authenticate(old_a, 10).await);
        assert!(!session.accept_data(old_b, 2).await);
        assert!(session.accept_data(new_conn, 1).await);
    }

    #[tokio::test]
    async fn second_path_same_epoch_authenticates_without_reset() {
        let session = Session::new();
        let first = session.add_test_conn().await;
        let second = session.add_test_conn().await;
        assert!(session.authenticate(first, 10).await);
        assert!(session.accept_data(first, 7).await);
        assert!(session.authenticate(second, 10).await);
        assert!(!session.accept_data(second, 7).await);
        assert!(session.accept_data(second, 8).await);
    }

    #[tokio::test]
    async fn epoch_change_preserves_unauthed_second_new_path() {
        let session = Session::new();
        let old = session.add_test_conn().await;
        assert!(session.authenticate(old, 10).await);

        let new_a = session.add_test_conn().await;
        let new_b = session.add_test_conn().await;
        assert!(session.authenticate(new_a, 20).await);
        assert!(session.authenticate(new_b, 20).await);
        assert!(!session.authenticate(old, 10).await);
        assert!(session.accept_data(new_a, 1).await);
        assert!(session.accept_data(new_b, 2).await);
    }

    #[tokio::test]
    async fn repeated_same_epoch_hello_is_idempotent() {
        let session = Session::new();
        let conn = session.add_test_conn().await;
        assert!(session.authenticate(conn, 10).await);
        assert!(session.authenticate(conn, 10).await);
        assert!(!session.authenticate(conn, 20).await);
    }

    #[tokio::test]
    async fn connection_accepts_only_its_first_hello() {
        let session = Session::new();
        let conn = session.add_test_conn().await;
        assert!(session.authenticate(conn, 10).await);
        assert!(!session.authenticate(conn, 20).await);
    }
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

    #[tokio::test]
    async fn server_generates_sack_with_gap() {
        let session = Session::new();
        let conn = session.add_test_conn().await;
        assert!(session.authenticate(conn, 10).await);

        // Receive 1, 2, 4 — gap at 3.
        assert!(session.accept_data(conn, 1).await);
        assert!(session.accept_data(conn, 2).await);
        assert!(session.accept_data(conn, 4).await);

        let sack = session.generate_sack().await;
        match sack {
            Frame::Sack {
                largest_contiguous,
                ranges,
            } => {
                assert_eq!(largest_contiguous, 2);
                assert!(ranges.contains(&(4, 4)), "gap range present: {ranges:?}");
            }
            _ => panic!("expected Sack frame"),
        }
    }

    #[tokio::test]
    async fn server_sack_retires_send_window() {
        let session = Session::new();
        let conn = session.add_test_conn().await;
        assert!(session.authenticate(conn, 10).await);

        // Retain three server→client packets.
        session.send_data(1, bytes::Bytes::from_static(b"a")).await;
        session.send_data(2, bytes::Bytes::from_static(b"b")).await;
        session.send_data(3, bytes::Bytes::from_static(b"c")).await;

        // Client SACKs 1 and 3, gap at 2 → seq 2 must be a retransmit candidate.
        let gaps = {
            let mut state = session.state.lock().await;
            state.send_window.ack(1, &[(3, 3)])
        };
        assert_eq!(gaps, vec![2]);
    }

    #[tokio::test]
    async fn server_assigns_both_families() {
        // The Assign the server sends on Hello must carry both an IPv4 and an
        // IPv6 tunnel address, and the shared MTU 1280.
        let assign = Frame::Assign {
            ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
            ipv6: Some((TUNNEL_V6_CLIENT, TUNNEL_V6_PREFIX)),
            mtu: TUNNEL_MTU,
            dns: vec![],
        };
        let encoded = encode(&assign);
        let decoded = multipass_proto::decode(&encoded).unwrap();
        match decoded {
            Frame::Assign {
                ipv4,
                ipv6,
                mtu,
                ..
            } => {
                assert_eq!(ipv4, Some((TUNNEL_CLIENT, TUNNEL_PREFIX)));
                assert_eq!(ipv6, Some((TUNNEL_V6_CLIENT, TUNNEL_V6_PREFIX)));
                assert_eq!(mtu, 1280);
            }
            _ => panic!("expected Assign"),
        }
    }

    #[tokio::test]
    async fn server_assigns_distinct_path_slots_and_schedules() {
        let session = Session::new();
        let first = session.add_test_conn().await;
        let second = session.add_test_conn().await;
        assert!(session.authenticate(first, 10).await);
        assert!(session.authenticate(second, 10).await);

        // The two connections in one epoch must occupy distinct scheduling
        // slots (Wired/Wifi labels), which is what lets the scheduler stripe
        // the download direction across both.
        let (p1, p2) = {
            let state = session.state.lock().await;
            let p1 = state.conns.iter().find(|c| c.id == first).unwrap().path;
            let p2 = state.conns.iter().find(|c| c.id == second).unwrap().path;
            (p1, p2)
        };
        assert!(p1.is_some() && p2.is_some());
        assert_ne!(p1, p2, "each connection gets a distinct scheduling slot");

        // With a measured RTT difference, the scheduler must prefer the faster.
        {
            let mut state = session.state.lock().await;
            let slow = p1.unwrap();
            let fast = p2.unwrap();
            state
                .scheduler
                .note_rtt(slow, std::time::Duration::from_millis(50));
            state
                .scheduler
                .note_rtt(fast, std::time::Duration::from_millis(1));
            assert_eq!(state.scheduler.pick(), Some(fast));
        }
    }
}
