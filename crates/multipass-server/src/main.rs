//! multipass-server — the authenticated router side of the multipass VPN.
//!
//! One logical client session may use any number of mutually authenticated
//! uplink connections. The current tunnel address contract serves one active
//! client identity at a time.

mod config;
mod identity;
mod tun;

use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use multipass_proto::{
    ClientId, Frame, PathId, ReorderBuffer, ReorderInsert, SackScoreboard, Scheduler, SendWindow,
    TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_PREFIX, UplinkId, encode,
};
use noq::{Connection, Endpoint, TransportConfig};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

/// Outbound/inbound channel capacity to/from the TUN reader/writer threads.
const TUN_CHANNEL: usize = 1024;
const REORDER_GAP_TIMEOUT: Duration = Duration::from_millis(50);

fn transport() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_multipath_paths(2);
    tc.initial_mtu(1_400);
    tc.min_mtu(1_400);
    tc.max_idle_timeout(Some(
        Duration::from_secs(2)
            .try_into()
            .expect("valid idle timeout"),
    ));
    tc.keep_alive_interval(Some(Duration::from_millis(200)));
    Arc::new(tc)
}

/// One client connection and its authenticated uplink registration.
struct LiveConn {
    id: u64,
    conn: Option<Connection>,
    epoch: Option<u64>,
    uplink_id: Option<UplinkId>,
    path_id: Option<PathId>,
    generation: Option<u64>,
}

struct SessionState {
    conns: Vec<LiveConn>,
    active_client_id: Option<ClientId>,
    epoch: Option<u64>,
    retired_epochs: HashSet<u64>,
    /// Receive scoreboard for client→server packets; generates SACKs.
    scoreboard: SackScoreboard,
    /// Admitted striped arrivals waiting for contiguous TUN delivery.
    reorder: ReorderBuffer<Bytes>,
    /// Last admitted arrival while a sequence gap may be pending.
    reorder_activity: Instant,
    /// Retention window for server→client packets (aggregation retransmit).
    send_window: SendWindow,
    /// Path scheduler for server→client aggregation (the download direction).
    scheduler: Scheduler,
}

struct UplinkAuthentication<'a> {
    authenticated_client_id: &'a ClientId,
    claimed_client_id: &'a ClientId,
    connection_id: u64,
    epoch: u64,
    uplink_id: UplinkId,
    path_id: PathId,
    generation: u64,
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
                active_client_id: None,
                epoch: None,
                retired_epochs: HashSet::new(),
                scoreboard: SackScoreboard::new(),
                reorder: ReorderBuffer::new(4096),
                reorder_activity: Instant::now(),
                send_window: SendWindow::new(4096),
                scheduler: Scheduler::new(),
            }),
            next_conn_id: AtomicU64::new(0),
            seq: AtomicU64::new(1),
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
            uplink_id: None,
            path_id: None,
            generation: None,
        });
        debug!(id, "connection added to session");
        id
    }

    async fn remove_conn(&self, id: u64) {
        let mut state = self.state.lock().await;
        if let Some(path_id) = state
            .conns
            .iter()
            .find(|conn| conn.id == id)
            .and_then(|conn| conn.path_id)
        {
            state.scheduler.set_eligible(path_id, false);
            state.scheduler.remove(path_id);
        }
        state.conns.retain(|conn| conn.id != id);
        debug!(id, "connection removed from session");
    }

    async fn authenticate_uplink(&self, authentication: UplinkAuthentication<'_>) -> bool {
        let UplinkAuthentication {
            authenticated_client_id,
            claimed_client_id,
            connection_id: id,
            epoch,
            uplink_id,
            path_id,
            generation,
        } = authentication;
        if authenticated_client_id != claimed_client_id {
            return false;
        }
        let mut state = self.state.lock().await;
        if let Some(active) = &state.active_client_id
            && active != authenticated_client_id
        {
            return false;
        }
        let Some(index) = state.conns.iter().position(|conn| conn.id == id) else {
            return false;
        };
        if let Some(authenticated_epoch) = state.conns[index].epoch {
            return authenticated_epoch == epoch
                && state.conns[index].uplink_id.as_ref() == Some(&uplink_id)
                && state.conns[index].path_id == Some(path_id)
                && state.conns[index].generation == Some(generation);
        }
        if state.retired_epochs.contains(&epoch) {
            return false;
        }

        let replacing_epoch = state.epoch != Some(epoch);
        let mut replace_connection_id = None;
        if !replacing_epoch {
            // Per-uplink generations are scoped to one client epoch. Only
            // registrations joining the active epoch compete with its paths.
            for existing in state
                .conns
                .iter()
                .filter(|conn| conn.id != id && conn.epoch == Some(epoch))
            {
                if existing.path_id == Some(path_id)
                    && existing.uplink_id.as_ref() != Some(&uplink_id)
                {
                    return false;
                }
                if existing.uplink_id.as_ref() == Some(&uplink_id) {
                    if existing.path_id != Some(path_id)
                        || generation <= existing.generation.unwrap_or(0)
                    {
                        return false;
                    }
                    replace_connection_id = Some(existing.id);
                }
            }
        }

        if replacing_epoch {
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
            state.scoreboard = SackScoreboard::new();
            state.reorder = ReorderBuffer::new(4096);
            state.reorder_activity = Instant::now();
            state.send_window = SendWindow::new(4096);
            state.scheduler = Scheduler::new();
            self.seq.store(1, Ordering::Relaxed);
        } else if let Some(replace_id) = replace_connection_id
            && let Some(existing_index) = state.conns.iter().position(|conn| conn.id == replace_id)
        {
            if let Some(handle) = state.conns[existing_index].conn.take() {
                handle.close(0u32.into(), b"uplink generation replaced");
            }
            state.conns.remove(existing_index);
        }

        let Some(conn) = state.conns.iter_mut().find(|conn| conn.id == id) else {
            return false;
        };
        conn.epoch = Some(epoch);
        conn.uplink_id = Some(uplink_id);
        conn.path_id = Some(path_id);
        conn.generation = Some(generation);
        state.scheduler.insert(path_id);
        state.scheduler.set_eligible(path_id, true);
        if state.active_client_id.is_none() {
            state.active_client_id = Some(authenticated_client_id.clone());
        }
        true
    }

    #[cfg(test)]
    async fn authenticate(&self, id: u64, epoch: u64) -> bool {
        let client_id = ClientId::new("test-client").unwrap();
        self.authenticate_uplink(UplinkAuthentication {
            authenticated_client_id: &client_id,
            claimed_client_id: &client_id,
            connection_id: id,
            epoch,
            uplink_id: UplinkId::new(format!("test-{id}")).unwrap(),
            path_id: PathId::new(u16::try_from(id + 1).unwrap()),
            generation: 1,
        })
        .await
    }

    #[cfg(test)]
    async fn accept_data(&self, id: u64, seq: u64) -> bool {
        let mut state = self.state.lock().await;
        let Some(conn) = state.conns.iter().find(|conn| conn.id == id) else {
            return false;
        };
        if conn.epoch != state.epoch || conn.epoch.is_none() {
            return false;
        }
        match state.reorder.insert(seq, Bytes::from_static(b"test")) {
            ReorderInsert::Rejected => false,
            ReorderInsert::Admitted => {
                state.scoreboard.insert(seq);
                true
            }
            ReorderInsert::AdmittedAfterSkipping { last, .. } => {
                state.scoreboard.abandon_through(last);
                state.scoreboard.insert(seq);
                true
            }
        }
    }

    async fn accept_packet(&self, id: u64, seq: u64, packet: Bytes) -> Vec<Bytes> {
        let mut state = self.state.lock().await;
        let Some(conn) = state.conns.iter().find(|conn| conn.id == id) else {
            return Vec::new();
        };
        if conn.epoch != state.epoch || conn.epoch.is_none() {
            return Vec::new();
        }
        match state.reorder.insert(seq, packet) {
            ReorderInsert::Rejected => {
                debug!(
                    seq,
                    next_seq = state.reorder.next_seq(),
                    occupancy = state.reorder.occupancy(),
                    span = ?state.reorder.buffered_span(),
                    "server reorder rejected arriving packet"
                );
                return Vec::new();
            }
            ReorderInsert::Admitted => {
                state.scoreboard.insert(seq);
            }
            ReorderInsert::AdmittedAfterSkipping { first, last } => {
                debug!(
                    seq,
                    first,
                    last,
                    next_seq = state.reorder.next_seq(),
                    occupancy = state.reorder.occupancy(),
                    span = ?state.reorder.buffered_span(),
                    "server reorder window boundary skipped missing prefix"
                );
                state.scoreboard.abandon_through(last);
                state.scoreboard.insert(seq);
            }
        }
        state.reorder_activity = Instant::now();
        let mut ready = Vec::new();
        while let Some(packet) = state.reorder.pop_ready() {
            ready.push(packet);
        }
        ready
    }

    async fn release_timed_out_gap(&self) -> Vec<Bytes> {
        let mut state = self.state.lock().await;
        if !state.reorder.has_gap() || state.reorder_activity.elapsed() < REORDER_GAP_TIMEOUT {
            return Vec::new();
        }
        let Some((first, last)) = state.reorder.skip_missing_prefix() else {
            return Vec::new();
        };
        debug!(
            first,
            last,
            next_seq = state.reorder.next_seq(),
            occupancy = state.reorder.occupancy(),
            span = ?state.reorder.buffered_span(),
            "server reorder gap timed out; releasing buffered suffix"
        );
        state.scoreboard.abandon_through(last);
        state.reorder_activity = Instant::now();
        let mut ready = Vec::new();
        while let Some(packet) = state.reorder.pop_ready() {
            ready.push(packet);
        }
        ready
    }

    /// Generate a SACK describing client→server receive state.
    async fn generate_sack(&self) -> Frame {
        let state = self.state.lock().await;
        state.scoreboard.generate_sack()
    }

    /// Whether any connection is authenticated for the current epoch. Used to
    /// gate TUN reads and SACK broadcasts so the server doesn't buffer or
    /// broadcast into a session with no live client.
    async fn has_live_conns(&self) -> bool {
        let state = self.state.lock().await;
        let epoch = state.epoch;
        state
            .conns
            .iter()
            .any(|c| c.epoch == epoch && c.conn.is_some())
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
        let stats: Vec<(PathId, Option<noq_proto::PathStats>, usize)> = state
            .conns
            .iter()
            .filter(|live| live.epoch == epoch)
            .filter_map(|live| {
                let path_id = live.path_id?;
                let conn = live.conn.as_ref()?;
                Some((
                    path_id,
                    conn.path_stats(noq_proto::PathId::ZERO),
                    conn.datagram_send_buffer_space(),
                ))
            })
            .collect();
        for (path, path_stats, space) in stats {
            if let Some(path_stats) = path_stats {
                state
                    .scheduler
                    .note_path_stats(path, path_stats.rtt, path_stats.cwnd);
            }
            state.scheduler.note_queue_space(path, space);
        }

        let Some(chosen) = state.scheduler.pick() else {
            return false;
        };
        for live in state.conns.iter_mut() {
            if live.epoch != epoch || live.path_id != Some(chosen) {
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
            uplink_id: None,
            path_id: None,
            generation: None,
        });
        id
    }
}

fn server_assignment(ipv6_client: Ipv6Addr) -> Frame {
    Frame::Assign {
        ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
        ipv6: Some((ipv6_client, 64)),
        mtu: TUNNEL_MTU,
        dns: vec![],
        server_version: env!("MULTIPASS_BUILD_COMMIT").into(),
    }
}

/// Drive one mutually authenticated client connection.
async fn conn_handler(
    conn: Connection,
    authenticated_client_id: ClientId,
    id: u64,
    session: Arc<Session>,
    to_tun: mpsc::Sender<Bytes>,
    ipv6_client: Ipv6Addr,
) {
    loop {
        match conn.read_datagram().await {
            Ok(d) => {
                let Some(frame) = multipass_proto::decode(&d) else {
                    debug!(id, len = d.len(), "malformed datagram dropped");
                    continue;
                };
                match frame {
                    Frame::Hello {
                        client_id,
                        client_epoch,
                        uplink_id,
                        path_id,
                        connection_generation,
                    } => {
                        if !session
                            .authenticate_uplink(UplinkAuthentication {
                                authenticated_client_id: &authenticated_client_id,
                                claimed_client_id: &client_id,
                                connection_id: id,
                                epoch: client_epoch,
                                uplink_id: uplink_id.clone(),
                                path_id,
                                generation: connection_generation,
                            })
                            .await
                        {
                            break;
                        }
                        let assign = server_assignment(ipv6_client);
                        if conn.send_datagram(encode(&assign)).is_err() {
                            break;
                        }
                        info!(id, client = %authenticated_client_id, client_epoch, uplink = %uplink_id, path_id = path_id.get(), connection_generation, "answered authenticated Hello: assigned");
                    }
                    Frame::Data { seq, packet } => {
                        for packet in session.accept_packet(id, seq, packet).await {
                            if to_tun.send(packet).await.is_err() {
                                return;
                            }
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

async fn run(
    runtime: config::ServerRuntimeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config::ServerRuntimeConfig { config, identity } = runtime;
    let base = u128::from(config.routed_ipv6_prefix);
    let ipv6_server = Ipv6Addr::from(base | 1);
    let ipv6_client = Ipv6Addr::from(base | 2);
    let tun = tun::open(ipv6_server)?;
    info!(name = %tun.name, ipv6 = %ipv6_server, "TUN device up");

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

    let authorized_clients = identity::AuthorizedClients::new(&config.authorized_clients);
    let server_tls = identity::server_config(&identity, authorized_clients.clone(), transport())?;
    let server = Endpoint::server(server_tls, config.bind)?;
    info!(addr = %server.local_addr()?, server_key = %identity.public_key(), "listening for authenticated client connections");

    let session = Arc::new(Session::new());
    // A missing striped packet can stall inner TCP, so recovery must not wait
    // for another arrival. Periodically abandon timed-out missing prefixes and
    // release the already-admitted suffix to the TUN.
    let reorder_session = session.clone();
    let reorder_to_tun = to_tun_tx.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            for packet in reorder_session.release_timed_out_gap().await {
                if reorder_to_tun.send(packet).await.is_err() {
                    return;
                }
            }
        }
    });

    // Periodic SACK broadcast so the client can retire/retransmit its window.
    let sack_session = session.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if sack_session.has_live_conns().await {
                sack_session.broadcast_sack().await;
            }
        }
    });

    loop {
        tokio::select! {
            // A new client connection (wired or wifi). Accept it into the session.
            incoming = server.accept() => {
                let Some(incoming) = incoming else { break };
                let session = session.clone();
                let to_tun = to_tun_tx.clone();
                let authorized_clients = authorized_clients.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => { warn!(%e, "mutual-auth handshake failed"); return; }
                    };
                    let authenticated_client_id = match authorized_clients.client_id_for_connection(&conn) {
                        Ok(id) => id,
                        Err(error) => { warn!(%error, "authenticated peer identity unavailable"); return; }
                    };
                    let remote = conn.path(noq_proto::PathId::ZERO)
                        .and_then(|p| p.remote_address().ok());
                    info!(client = %authenticated_client_id, remote = ?remote, "authenticated client connection established");
                    let id = session.add_conn(conn.clone()).await;
                    conn_handler(conn, authenticated_client_id.clone(), id, session.clone(), to_tun, ipv6_client).await;
                    session.remove_conn(id).await;
                    info!(id, client = %authenticated_client_id, remote = ?remote, "client connection closed");
                });
            }
            // A packet read from the TUN: aggregate onto the best live connection.
            maybe = from_tun_rx.recv() => {
                let Some(packet) = maybe else { break }; // TUN reader died
                // Drop packets when no client session is live rather than
                // filling the retention window with undeliverable data.
                if !session.has_live_conns().await {
                    continue;
                }
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

    let args = std::env::args().collect::<Vec<_>>();
    let config_path = match args.as_slice() {
        [_, flag, path] if flag == "--config" => path,
        [program, ..] => return Err(format!("usage: {program} --config <path>").into()),
        [] => return Err("usage: multipass-server --config <path>".into()),
    };
    let config = config::ServerConfigFile::load_validated_runtime(config_path)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(config))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::{Frame, REORDER_GAP_TIMEOUT, Session, UplinkAuthentication, server_assignment};
    use multipass_proto::{ClientId, PathId, TUNNEL_CLIENT, TUNNEL_PREFIX, UplinkId, encode};

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
    async fn new_client_epoch_restarts_server_data_sequence() {
        let session = Session::new();
        let old = session.add_test_conn().await;
        assert!(session.authenticate(old, 10).await);
        assert_eq!(session.next_seq(), 1);
        assert_eq!(session.next_seq(), 2);

        let new = session.add_test_conn().await;
        assert!(session.authenticate(new, 20).await);
        assert_eq!(session.next_seq(), 1);
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
    async fn server_releases_buffered_suffix_after_gap_timeout_without_new_arrivals() {
        let session = Session::new();
        let conn = session.add_test_conn().await;
        assert!(session.authenticate(conn, 10).await);

        assert!(
            session
                .accept_packet(conn, 2, Bytes::from_static(b"two"))
                .await
                .is_empty()
        );
        assert!(
            session
                .accept_packet(conn, 3, Bytes::from_static(b"three"))
                .await
                .is_empty()
        );
        tokio::time::sleep(REORDER_GAP_TIMEOUT + Duration::from_millis(10)).await;

        let ready = session.release_timed_out_gap().await;
        assert_eq!(
            ready,
            vec![Bytes::from_static(b"two"), Bytes::from_static(b"three")]
        );
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

        // Reordering is not declared loss until three consecutive SACKs.
        let mut state = session.state.lock().await;
        assert!(state.send_window.ack(1, &[(3, 3)]).is_empty());
        assert!(state.send_window.ack(1, &[(3, 3)]).is_empty());
        assert_eq!(state.send_window.ack(1, &[(3, 3)]), vec![2]);
    }

    #[test]
    fn configured_prefix_drives_server_and_client_addresses() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 0);
        let ipv6_server = Ipv6Addr::from(u128::from(prefix) | 1);
        let ipv6_client = Ipv6Addr::from(u128::from(prefix) | 2);

        let assign = server_assignment(ipv6_client);
        let encoded = encode(&assign);
        let decoded = multipass_proto::decode(&encoded).unwrap();
        match decoded {
            Frame::Assign {
                ipv4, ipv6, mtu, ..
            } => {
                assert_eq!(ipv4, Some((TUNNEL_CLIENT, TUNNEL_PREFIX)));
                assert_eq!(ipv6, Some(("2001:db8:1234:5678::2".parse().unwrap(), 64)));
                assert_eq!(
                    ipv6_server,
                    "2001:db8:1234:5678::1".parse::<Ipv6Addr>().unwrap()
                );
                assert_eq!(mtu, 1280);
            }
            _ => panic!("expected Assign"),
        }
    }

    #[test]
    fn server_assign_carries_compile_time_build_identity() {
        match server_assignment("2001:db8::2".parse().unwrap()) {
            Frame::Assign { server_version, .. } => {
                assert_eq!(server_version, env!("MULTIPASS_BUILD_COMMIT"));
                assert!(!server_version.is_empty());
            }
            _ => panic!("expected Assign"),
        }
    }
    fn client() -> ClientId {
        ClientId::new("test-client").unwrap()
    }

    async fn authenticate_uplink(
        session: &Session,
        conn: u64,
        epoch: u64,
        uplink: &str,
        path: u16,
        generation: u64,
    ) -> bool {
        let client = client();
        session
            .authenticate_uplink(UplinkAuthentication {
                authenticated_client_id: &client,
                claimed_client_id: &client,
                connection_id: conn,
                epoch,
                uplink_id: UplinkId::new(uplink).unwrap(),
                path_id: PathId::new(path),
                generation,
            })
            .await
    }

    #[tokio::test]
    async fn server_registers_three_explicit_uplinks_in_one_epoch() {
        let session = Session::new();
        for id in 1..=3 {
            let conn = session.add_test_conn().await;
            assert!(
                authenticate_uplink(&session, conn, 10, &format!("uplink-{id}"), id as u16, 1,)
                    .await
            );
        }
        let state = session.state.lock().await;
        assert_eq!(
            state
                .conns
                .iter()
                .filter(|conn| conn.epoch == Some(10))
                .count(),
            3
        );
        assert_eq!(state.scheduler.len(), 3);
    }

    #[tokio::test]
    async fn newer_uplink_generation_supersedes_only_matching_connection() {
        let session = Session::new();
        let old_wifi = session.add_test_conn().await;
        let ethernet = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, old_wifi, 10, "wifi", 1, 1).await);
        assert!(authenticate_uplink(&session, ethernet, 10, "ethernet", 2, 1).await);

        let new_wifi = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, new_wifi, 10, "wifi", 1, 2).await);
        assert!(!authenticate_uplink(&session, old_wifi, 10, "wifi", 1, 1).await);
        assert!(session.accept_data(ethernet, 1).await);
        assert!(session.accept_data(new_wifi, 2).await);
    }

    #[tokio::test]
    async fn server_rejects_stale_generation_and_conflicting_path_id() {
        let session = Session::new();
        let wifi = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, wifi, 10, "wifi", 1, 3).await);

        let stale = session.add_test_conn().await;
        assert!(!authenticate_uplink(&session, stale, 10, "wifi", 1, 2).await);
        let conflict = session.add_test_conn().await;
        assert!(!authenticate_uplink(&session, conflict, 10, "ethernet", 1, 1).await);
    }

    #[tokio::test]
    async fn retired_epoch_rejection_does_not_mutate_valid_session() {
        let session = Session::new();
        let old = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, old, 10, "wifi", 1, 3).await);
        let current = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, current, 20, "wifi", 1, 0).await);

        let rollback = session.add_test_conn().await;
        assert!(!authenticate_uplink(&session, rollback, 10, "ethernet", 2, 0).await);
        assert_eq!(session.state.lock().await.epoch, Some(20));
        assert!(session.accept_data(current, 1).await);
    }

    #[tokio::test]
    async fn new_epoch_restarts_uplink_generation() {
        let session = Session::new();
        let old = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, old, 10, "wifi", 1, 3).await);

        let restarted = session.add_test_conn().await;
        assert!(authenticate_uplink(&session, restarted, 20, "wifi", 1, 0).await);
        assert_eq!(session.state.lock().await.epoch, Some(20));
        assert!(session.accept_data(restarted, 1).await);
    }

    #[tokio::test]
    async fn claimed_client_id_mismatch_is_rejected_before_session_mutation() {
        let session = Session::new();
        let conn = session.add_test_conn().await;
        let authenticated = ClientId::new("scooter").unwrap();
        let claimed = ClientId::new("intruder").unwrap();

        assert!(
            !session
                .authenticate_uplink(UplinkAuthentication {
                    authenticated_client_id: &authenticated,
                    claimed_client_id: &claimed,
                    connection_id: conn,
                    epoch: 10,
                    uplink_id: UplinkId::new("wifi").unwrap(),
                    path_id: PathId::new(1),
                    generation: 1,
                })
                .await
        );
        assert!(session.state.lock().await.active_client_id.is_none());
    }

    #[tokio::test]
    async fn rejected_first_hello_does_not_claim_active_client_identity() {
        let session = Session::new();
        {
            let mut state = session.state.lock().await;
            state.retired_epochs.insert(10);
        }

        let rejected_conn = session.add_test_conn().await;
        let first = ClientId::new("scooter").unwrap();
        assert!(
            !session
                .authenticate_uplink(UplinkAuthentication {
                    authenticated_client_id: &first,
                    claimed_client_id: &first,
                    connection_id: rejected_conn,
                    epoch: 10,
                    uplink_id: UplinkId::new("wifi").unwrap(),
                    path_id: PathId::new(1),
                    generation: 1,
                })
                .await
        );
        assert!(session.state.lock().await.active_client_id.is_none());

        let accepted_conn = session.add_test_conn().await;
        let second = ClientId::new("laptop").unwrap();
        assert!(
            session
                .authenticate_uplink(UplinkAuthentication {
                    authenticated_client_id: &second,
                    claimed_client_id: &second,
                    connection_id: accepted_conn,
                    epoch: 20,
                    uplink_id: UplinkId::new("ethernet").unwrap(),
                    path_id: PathId::new(2),
                    generation: 1,
                })
                .await
        );
        assert_eq!(
            session.state.lock().await.active_client_id.as_ref(),
            Some(&second)
        );
    }

    #[tokio::test]
    async fn second_authorized_identity_is_rejected_without_mutating_active_session() {
        let session = Session::new();
        let first_conn = session.add_test_conn().await;
        let first = ClientId::new("scooter").unwrap();
        assert!(
            session
                .authenticate_uplink(UplinkAuthentication {
                    authenticated_client_id: &first,
                    claimed_client_id: &first,
                    connection_id: first_conn,
                    epoch: 10,
                    uplink_id: UplinkId::new("wifi").unwrap(),
                    path_id: PathId::new(1),
                    generation: 1,
                })
                .await
        );

        let second_conn = session.add_test_conn().await;
        let second = ClientId::new("laptop").unwrap();
        assert!(
            !session
                .authenticate_uplink(UplinkAuthentication {
                    authenticated_client_id: &second,
                    claimed_client_id: &second,
                    connection_id: second_conn,
                    epoch: 20,
                    uplink_id: UplinkId::new("ethernet").unwrap(),
                    path_id: PathId::new(2),
                    generation: 1,
                })
                .await
        );
        let state = session.state.lock().await;
        assert_eq!(state.active_client_id.as_ref(), Some(&first));
        assert_eq!(state.epoch, Some(10));
    }

    #[tokio::test]
    async fn server_assigns_distinct_path_slots_and_schedules() {
        let session = Session::new();
        let first = session.add_test_conn().await;
        let second = session.add_test_conn().await;
        assert!(session.authenticate(first, 10).await);
        assert!(session.authenticate(second, 10).await);

        // Explicit path IDs let the scheduler stripe the download direction
        // across any number of registered uplinks.
        let (p1, p2) = {
            let state = session.state.lock().await;
            let p1 = state.conns.iter().find(|c| c.id == first).unwrap().path_id;
            let p2 = state.conns.iter().find(|c| c.id == second).unwrap().path_id;
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
