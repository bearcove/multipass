//! multipassd — the privileged multipass client daemon (macOS, root).
//!
//! Owns the tunnel: creates a utun device, assigns the tunnel IP + MTU,
//! installs full-tunnel routing, and pumps raw IP packets between the utun
//! and the multipass failover transport (`multipass::Transport`).
//!
//! # utun creation (macOS)
//!
//! There is no `/dev/net/tun` on macOS. We hand-roll the kernel-control
//! socket (see `utun.rs`):
//!
//!   1. `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
//!   2. `ioctl(fd, CTLIOCGINFO, &ctl_info)` to resolve
//!      `"com.apple.net.utun_control"` to a `ctl_id`
//!   3. `connect(fd, sockaddr_ctl { sc_id, sc_unit: 0 })` — `sc_unit = 0`
//!      auto-assigns the next free `utunN`; the unit is read back from
//!      `getsockname`.
//!   4. The socket is the tunnel.
//!
//! # The 4-byte address-family header
//!
//! Every utun packet is prefixed with a 4-byte big-endian `u32` address
//! family (`AF_INET = 2`). We strip it on read and prepend it on write.
//! Non-`AF_INET` frames are dropped.
//!
//! # Routing
//!
//! Full-tunnel: after the server's `Assign`, we (a) pin the server's underlay
//! address to the physical interfaces with `-ifscope` host routes so the
//! tunnel's own QUIC never recurses, then (b) install the default via utun.
//! See `routes.rs`.
//!
//! # Pump structure (why a utun-reader task)
//!
//! `multipass::Transport` takes `&mut self` for its receive methods, so one
//! select can arm only a single receive at a time and cannot hold
//! `send_data(&self)` and `recv_data(&mut self)` together. We therefore split
//! the pump: a utun-reader task forwards outbound packets over an mpsc
//! channel, and the pump owns the `Transport` and selects over
//! {channel -> send_data, recv_data -> utun, 500ms reconnect tick}.

mod ipc;
mod routes;
mod utun;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use multipass::{PathKind, Transport};
use multipass_proto::{Frame, TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_SERVER};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

/// Snapshot of path liveness + RTT, published by the pump for the IPC server.
/// Kept off the transport so IPC never contends with the pump's `&mut self`.
#[derive(Debug, Clone, Copy)]
pub struct PathSnapshot {
    pub wired_alive: bool,
    pub wifi_alive: bool,
    pub wired_rtt_ms: Option<f64>,
    pub wifi_rtt_ms: Option<f64>,
    pub active: Option<PathKind>,
}

/// Live daemon state shared between the pump and the IPC server.
pub struct Shared {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub enabled: AtomicBool,
    pub active: AtomicBool,
    pub paths: RwLock<PathSnapshot>,
    pub server: SocketAddr,
    pub wired_src: IpAddr,
    pub wifi_src: IpAddr,
    pub wired_iface: String,
    pub wifi_iface: String,
    pub utun_name: String,
}

impl Shared {
    fn new(opts: &Opts, wired_iface: String, wifi_iface: String, utun_name: String) -> Arc<Shared> {
        Arc::new(Shared {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            active: AtomicBool::new(false),
            paths: RwLock::new(PathSnapshot {
                wired_alive: false,
                wifi_alive: false,
                wired_rtt_ms: None,
                wifi_rtt_ms: None,
                active: None,
            }),
            server: opts.server,
            wired_src: opts.wired,
            wifi_src: opts.wifi,
            wired_iface,
            wifi_iface,
            utun_name,
        })
    }
}

struct Opts {
    server: SocketAddr,
    wired: IpAddr,
    wifi: IpAddr,
    socket: String,
}

fn parse_args() -> Result<Opts, String> {
    let args: Vec<String> = std::env::args().collect();
    // multipassd <server:port> <wired-ip> <wifi-ip> [socket-path]
    if args.len() < 4 {
        return Err("usage: multipassd <server:port> <wired-ip> <wifi-ip> [socket-path]".into());
    }
    let server = args[1]
        .parse()
        .map_err(|e| format!("bad server addr: {e}"))?;
    let wired = args[2].parse().map_err(|e| format!("bad wired ip: {e}"))?;
    let wifi = args[3].parse().map_err(|e| format!("bad wifi ip: {e}"))?;
    let socket = args
        .get(4)
        .cloned()
        .unwrap_or_else(|| ipc::DEFAULT_SOCKET.to_string());
    Ok(Opts {
        server,
        wired,
        wifi,
        socket,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multipassd=info,noq=warn".parse().unwrap()),
        )
        .init();

    let opts = parse_args()?;
    let ipc_server = ipc::bind(&opts.socket)?;
    info!(server = %opts.server, wired = %opts.wired, wifi = %opts.wifi, "multipassd starting");

    // Resolve physical interface names from the source IPs (for route pinning).
    let wired_iface = source_ipv4(&opts.wired)
        .and_then(utun::iface_for_ip)
        .unwrap_or_default();
    let wifi_iface = source_ipv4(&opts.wifi)
        .and_then(utun::iface_for_ip)
        .unwrap_or_default();
    warn!(
        wired = %opts.wired,
        wifi = %opts.wifi,
        wired_iface = %wired_iface,
        wifi_iface = %wifi_iface,
        "resolved physical interfaces"
    );

    // Open the utun once; it outlives transport reconnects.
    let utun_raw = utun::Utun::open()?;
    tracing::debug!(iface = %utun_raw.name(), "utun: kernel control socket open");
    let utun = Arc::new(AsyncFd::new(utun_raw)?);
    let utun_name = utun.get_ref().name();
    info!(iface = %utun_name, "utun open");
    let (tx_q, mut rx_q) = mpsc::channel::<Bytes>(256);
    spawn_utun_reader(utun.clone(), tx_q);
    let mut seq = 0u64;

    let shared = Shared::new(&opts, wired_iface, wifi_iface, utun_name);
    let ipc_shared = shared.clone();

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let ipc_task = tokio::spawn(async move {
        let result = ipc::serve(ipc_server, ipc_shared).await;
        let _ = shutdown_tx.send(true);
        result
    });
    let transport_lifecycle = async {
        loop {
            // Wait until enabled, but make IPC failure terminate the daemon.
            if !shared.enabled.load(Ordering::Relaxed) {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
                continue;
            }

            let client_nonce = new_client_nonce();
            let mut transport = match Transport::connect(opts.server, opts.wired, opts.wifi).await {
                Ok(t) => t,
                Err(e) => {
                    warn!(%e, "transport connect failed; retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            if *shutdown_rx.borrow() {
                break;
            }
            if !shared.enabled.load(Ordering::Relaxed) {
                continue;
            }

            if *shutdown_rx.borrow() {
                break;
            }
            match handshake(&mut transport, client_nonce).await {
                Ok((ipv4, ipv6, mtu)) => {
                    if !shared.enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    info!(?ipv4, ?ipv6, mtu, "assigned; configuring tunnel");
                    let utun_name = shared.utun_name.clone();
                    let Some((v4_addr, v4_prefix)) = ipv4 else {
                        error!("no IPv4 assignment received; disabling tunnel");
                        shared.enabled.store(false, Ordering::Relaxed);
                        continue;
                    };
                    if !routes::configure(&utun_name, v4_addr, v4_prefix, mtu) {
                        error!("tunnel interface configuration failed; disabling tunnel");
                        shared.enabled.store(false, Ordering::Relaxed);
                        continue;
                    }
                    if !shared.enabled.load(Ordering::Relaxed) {
                        continue;
                    }

                    let canary_ok = run_canary_pump(&mut transport, &shared, &mut seq).await;
                    if !canary_ok {
                        error!("dataplane canary failed; disabling tunnel");
                        shared.enabled.store(false, Ordering::Relaxed);
                        continue;
                    }
                    if !shared.enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    if !routes::setup(
                        &utun_name,
                        opts.server.ip(),
                        &shared.wired_iface,
                        &shared.wifi_iface,
                    ) {
                        error!("route activation failed; rolled back; disabling tunnel");
                        shared.enabled.store(false, Ordering::Relaxed);
                        continue;
                    }
                    if !shared.enabled.load(Ordering::Relaxed) {
                        routes::teardown(
                            &shared.utun_name,
                            opts.server.ip(),
                            &shared.wired_iface,
                            &shared.wifi_iface,
                        );
                        continue;
                    }
                    shared.active.store(true, Ordering::Relaxed);
                    let pump_end = pump(
                        utun.clone(),
                        &mut transport,
                        shared.clone(),
                        &mut rx_q,
                        &mut seq,
                        client_nonce,
                        &mut shutdown_rx,
                    )
                    .await;

                    shared.active.store(false, Ordering::Relaxed);
                    info!("transport inactive; restoring routes");
                    routes::teardown(
                        &shared.utun_name,
                        opts.server.ip(),
                        &shared.wired_iface,
                        &shared.wifi_iface,
                    );
                    match pump_end {
                        PumpEnd::Reconnect => info!("transport ended; re-dialing"),
                        PumpEnd::Shutdown => break,
                        PumpEnd::Fatal(e) => {
                            error!(%e, "pump fatal");
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    error!(%e, "handshake failed; re-dialing");
                    continue;
                }
            }

            if *shutdown_rx.borrow() {
                break;
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    let lifecycle_result = transport_lifecycle.await;
    if *shutdown_rx.borrow() {
        ipc_task.await??;
    } else {
        ipc_task.abort();
    }
    lifecycle_result
}

async fn handshake(
    transport: &mut Transport,
    client_nonce: u64,
) -> Result<(Option<(Ipv4Addr, u8)>, Option<(std::net::Ipv6Addr, u8)>, u16), Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut assignment = None;
    while PathKind::ALL.iter().any(|&kind| !transport.is_ready(kind)) {
        for kind in PathKind::ALL {
            if !transport.is_ready(kind) {
                transport.send_frame_on(kind, &Frame::Hello { client_nonce });
            }
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for both path assignments".into());
        }
        match tokio::time::timeout(
            remaining.min(Duration::from_millis(250)),
            transport.recv_control(),
        )
        .await
        {
            Ok(Some((path, Frame::Assign { ipv4, ipv6, mtu, .. }))) => {
                transport.mark_ready(path);
                assignment.get_or_insert((ipv4, ipv6, mtu));
            }
            Ok(Some((path, frame))) => {
                info!(path = %path.label(), ?frame, "control frame during handshake");
            }
            Ok(None) => return Err("transport closed during handshake".into()),
            Err(_) => {}
        }
    }
    assignment.ok_or_else(|| "no assignment received".into())
}

fn new_client_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64)
}

/// How the pump exited.
enum PumpEnd {
    /// Transport fully closed (both paths) — re-dial.
    Reconnect,
    /// Fatal daemon error.
    /// IPC ownership or listener failed; tear down routes and exit.
    Shutdown,
    Fatal(Box<dyn std::error::Error + Send + Sync>),
}

impl From<io::Error> for PumpEnd {
    fn from(e: io::Error) -> Self {
        PumpEnd::Fatal(Box::new(e))
    }
}

/// How often the pump re-checks path liveness and re-dials dead paths.
const RECONNECT_TICK: Duration = Duration::from_millis(500);
/// Minimum spacing between re-dial attempts for an already-failed path.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);

/// Prove the authenticated QUIC/server/TUN return path before installing routes.
async fn run_canary_pump(transport: &mut Transport, shared: &Shared, seq: &mut u64) -> bool {
    let (identifier, echo_sequence) = canary_identity(*seq);
    let packet = Bytes::copy_from_slice(&build_canary_request(identifier, echo_sequence));
    *seq += 1;
    if !transport.send_data(*seq, packet.clone()) {
        return false;
    }
    shared
        .tx_bytes
        .fetch_add(packet.len() as u64, Ordering::Relaxed);

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let Some(data) = transport.recv_data().await else {
                return false;
            };
            update_active(shared, data.path);
            shared
                .rx_bytes
                .fetch_add(data.packet.len() as u64, Ordering::Relaxed);
            match validate_canary_reply(&data.packet, identifier, echo_sequence) {
                Ok(()) => return true,
                Err(CanaryReject::Header) => {
                    debug!(len = data.packet.len(), "non-canary packet during canary")
                }
                Err(reason) => {
                    warn!(?reason, len = data.packet.len(), "canary reply rejected")
                }
            }
        }
    })
    .await
    .unwrap_or(false)
}
fn canary_identity(seq: u64) -> (u16, u16) {
    (0x4d50, seq as u16)
}

fn build_canary_request(identifier: u16, sequence: u16) -> [u8; 28] {
    let mut packet = [0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&TUNNEL_CLIENT.octets());
    packet[16..20].copy_from_slice(&TUNNEL_SERVER.octets());
    packet[20] = 8;
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    packet[26..28].copy_from_slice(&sequence.to_be_bytes());
    let icmp_checksum = internet_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanaryReject {
    Header,
    Protocol,
    Source,
    Destination,
    IcmpTypeCode,
    Identifier,
    Sequence,
    IpChecksum,
    IcmpChecksum,
}

fn validate_canary_reply(
    packet: &[u8],
    identifier: u16,
    sequence: u16,
) -> Result<(), CanaryReject> {
    if packet.len() != 28 || packet[0] >> 4 != 4 || packet[0] & 0x0f != 5 {
        return Err(CanaryReject::Header);
    }
    if packet[9] != 1 {
        return Err(CanaryReject::Protocol);
    }
    if packet[12..16] != TUNNEL_SERVER.octets() {
        return Err(CanaryReject::Source);
    }
    if packet[16..20] != TUNNEL_CLIENT.octets() {
        return Err(CanaryReject::Destination);
    }
    if packet[20] != 0 || packet[21] != 0 {
        return Err(CanaryReject::IcmpTypeCode);
    }
    if packet[24..26] != identifier.to_be_bytes() {
        return Err(CanaryReject::Identifier);
    }
    if packet[26..28] != sequence.to_be_bytes() {
        return Err(CanaryReject::Sequence);
    }
    if internet_checksum(&packet[..20]) != 0 {
        return Err(CanaryReject::IpChecksum);
    }
    if internet_checksum(&packet[20..]) != 0 {
        return Err(CanaryReject::IcmpChecksum);
    }
    Ok(())
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Pump packets while re-authenticating any re-dialed path before scheduling.
async fn pump(
    utun: Arc<AsyncFd<utun::Utun>>,
    transport: &mut Transport,
    shared: Arc<Shared>,
    rx_q: &mut mpsc::Receiver<Bytes>,
    seq: &mut u64,
    client_nonce: u64,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> PumpEnd {
    let mut wbuf = vec![0u8; TUNNEL_MTU as usize + 4];
    let mut backoff = [Instant::now(); 2];
    let mut tick = tokio::time::interval(RECONNECT_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // SACKs must flow back to the server fast enough that its retention window
    // can retransmit gaps within a few RTTs. 10ms is well under the path RTT
    // timescale for gap detection without flooding the control channel.
    let mut sack_tick = tokio::time::interval(Duration::from_millis(10));
    sack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return PumpEnd::Shutdown;
                }
            }
            _ = sack_tick.tick() => {
                transport.broadcast_sack();
            }
            Some(pkt) = rx_q.recv() => {
                if shared.enabled.load(Ordering::Relaxed) {
                    *seq += 1;
                    if transport.send_data(*seq, pkt.clone()) {
                        shared.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    }
                }
            }
            control = transport.recv_control() => {
                match control {
                    Some((path, Frame::Assign { .. })) => {
                        transport.mark_ready(path);
                        info!(path = %path.label(), "path epoch acknowledged");
                    }
                    Some((path, frame)) => {
                        info!(path = %path.label(), ?frame, "control frame during pump");
                    }
                    None => return PumpEnd::Reconnect,
                }
            }
            d = transport.recv_data() => {
                let Some(d) = d else { return PumpEnd::Reconnect };
                update_active(&shared, d.path);
                shared.rx_bytes.fetch_add(d.packet.len() as u64, Ordering::Relaxed);
                if shared.enabled.load(Ordering::Relaxed)
                    && let Err(e) = utun.get_ref().write_packet(&mut wbuf, &d.packet)
                {
                    warn!(%e, "utun write error");
                }
            }
            _ = tick.tick() => {
                if !shared.enabled.load(Ordering::Relaxed) {
                    return PumpEnd::Reconnect;
                }
                publish_status(transport, &shared);
                reconnect_dead(transport, &shared, &mut backoff, client_nonce).await;
            }
        }
    }
}

fn publish_status(transport: &Transport, shared: &Shared) {
    let st = transport.status();
    let active = shared.paths.read().unwrap().active;
    *shared.paths.write().unwrap() = PathSnapshot {
        wired_alive: st.wired.alive,
        wifi_alive: st.wifi.alive,
        wired_rtt_ms: st.wired.rtt.map(|d| d.as_secs_f64() * 1000.0),
        wifi_rtt_ms: st.wifi.rtt.map(|d| d.as_secs_f64() * 1000.0),
        active,
    };
}

fn update_active(shared: &Shared, kind: PathKind) {
    shared.paths.write().unwrap().active = Some(kind);
}

async fn reconnect_dead(
    transport: &Transport,
    shared: &Shared,
    backoff: &mut [Instant; 2],
    client_nonce: u64,
) {
    for kind in PathKind::ALL {
        let idx = match kind {
            PathKind::Wired => 0,
            PathKind::Wifi => 1,
        };
        if backoff[idx].elapsed() < RECONNECT_BACKOFF {
            continue;
        }

        if transport.is_alive(kind) {
            if !transport.is_ready(kind) {
                backoff[idx] = Instant::now();
                transport.send_frame_on(kind, &Frame::Hello { client_nonce });
            }
            continue;
        }

        backoff[idx] = Instant::now();
        let src = match kind {
            PathKind::Wired => shared.wired_src,
            PathKind::Wifi => shared.wifi_src,
        };
        match transport.reconnect_path(kind, shared.server, src).await {
            Ok(()) => {
                transport.send_frame_on(kind, &Frame::Hello { client_nonce });
                info!(path = %kind.label(), "path re-dialed; awaiting epoch acknowledgement");
            }
            Err(e) => warn!(path = %kind.label(), %e, "path re-dial failed; will retry"),
        }
    }
}

/// Read utun packets and forward them to the pump. Segregated so the pump can
/// own the `Transport` mutably without a send/receive borrow conflict.
fn spawn_utun_reader(utun: Arc<AsyncFd<utun::Utun>>, tx_q: mpsc::Sender<Bytes>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; TUNNEL_MTU as usize + 4];
        loop {
            match utun.readable().await {
                Ok(mut guard) => {
                    match guard.get_inner().read_packet(&mut buf) {
                        Ok(Some(n)) => {
                            let pkt = Bytes::copy_from_slice(&buf[..n]);
                            if tx_q.send(pkt).await.is_err() {
                                break; // pump gone
                            }
                        }
                        Ok(None) => { /* non-IPv4 frame, dropped */ }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            guard.clear_ready();
                        }
                        Err(e) => {
                            warn!(%e, "utun read error");
                        }
                    }
                }
                Err(e) => {
                    warn!(%e, "utun readable failed");
                    break;
                }
            }
        }
    });
}

/// Extract the IPv4 address from an `IpAddr` (we only tunnel IPv4).
fn source_ipv4(ip: &IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanaryReject, build_canary_request, canary_identity, internet_checksum,
        validate_canary_reply,
    };

    #[test]
    fn raw_canary_request_is_valid_ipv4_icmp() {
        let packet = build_canary_request(0x1234, 7);
        assert_eq!(packet.len(), 28);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(internet_checksum(&packet[20..]), 0);
        assert_eq!(&packet[12..16], &[10, 10, 99, 2]);
        assert_eq!(&packet[16..20], &[10, 10, 99, 1]);
        assert_eq!(packet[20], 8);
    }

    #[test]
    fn first_process_canary_uses_nonzero_identifier() {
        let (identifier, sequence) = canary_identity(0);
        assert_eq!(identifier, 0x4d50);
        assert_eq!(sequence, 0);

        let request = build_canary_request(identifier, sequence);
        assert_ne!(&request[22..24], &[0, 0]);
    }
    #[test]
    fn canary_identity_accepts_valid_zero_reply_checksum_at_b2af() {
        let (identifier, sequence) = canary_identity(0xb2af);
        let reply = build_canary_reply(identifier, sequence);

        assert_eq!(&reply[22..24], &[0, 0]);
        assert_eq!(validate_canary_reply(&reply, identifier, sequence), Ok(()));
    }

    fn build_canary_reply(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut reply = build_canary_request(identifier, sequence).to_vec();
        reply[12..16].copy_from_slice(&[10, 10, 99, 1]);
        reply[16..20].copy_from_slice(&[10, 10, 99, 2]);
        reply[20] = 0;
        reply[22..24].fill(0);
        let icmp_checksum = internet_checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        reply[10..12].fill(0);
        let ip_checksum = internet_checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        reply
    }

    #[test]
    fn raw_canary_reply_requires_matching_valid_echo() {
        let mut reply = build_canary_request(0x1234, 7).to_vec();
        reply[12..16].copy_from_slice(&[10, 10, 99, 1]);
        reply[16..20].copy_from_slice(&[10, 10, 99, 2]);
        reply[20] = 0;
        reply[22..24].fill(0);
        let icmp_checksum = internet_checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        reply[10..12].fill(0);
        let ip_checksum = internet_checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        assert_eq!(validate_canary_reply(&reply, 0x1234, 7), Ok(()));
        reply[22] ^= 1;
        assert_eq!(
            validate_canary_reply(&reply, 0x1234, 7),
            Err(CanaryReject::IcmpChecksum)
        );
    }
}
