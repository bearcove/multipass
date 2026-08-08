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
use multipass_proto::{Frame, TUNNEL_MTU};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

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
    let server = args[1].parse().map_err(|e| format!("bad server addr: {e}"))?;
    let wired = args[2].parse().map_err(|e| format!("bad wired ip: {e}"))?;
    let wifi = args[3].parse().map_err(|e| format!("bad wifi ip: {e}"))?;
    let socket = args.get(4).cloned().unwrap_or_else(|| ipc::DEFAULT_SOCKET.to_string());
    Ok(Opts { server, wired, wifi, socket })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multipassd=info,noq=warn".parse().unwrap()),
        )
        .init();

    let opts = parse_args()?;
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

    let shared = Shared::new(&opts, wired_iface, wifi_iface, utun_name);

    // IPC server (menubar app) runs for the daemon's whole life.
    let ipc_shared = shared.clone();
    let ipc_socket = opts.socket.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc::serve(&ipc_socket, ipc_shared).await {
            error!(%e, "ipc server failed");
        }
    });

    // Transport lifecycle, GATED on `enabled` (the app's Connect toggle).
    //
    // The daemon boots IDLE: it opens the utun + IPC socket and then waits.
    // Only when the menubar app sends `connect` (setting `enabled = true`) do
    // we dial, handshake, install routes, and pump. `disconnect` clears
    // `enabled`, which tears the transport down and restores routing. This is
    // the state machine that lets the app actually control the tunnel — and
    // keeps the IPC socket responsive the whole time (it runs on its own task).
    loop {
        // Wait until enabled.
        if !shared.enabled.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        let mut transport = match Transport::connect(opts.server, opts.wired, opts.wifi).await {
            Ok(t) => t,
            Err(e) => {
                warn!(%e, "transport connect failed; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if !shared.enabled.load(Ordering::Relaxed) {
            continue;
        }

        match handshake(&mut transport).await {
            Ok((addr, prefix, mtu)) => {
                if !shared.enabled.load(Ordering::Relaxed) {
                    continue;
                }
                info!(%addr, prefix, mtu, "assigned; configuring tunnel");
                let utun_name = shared.utun_name.clone();
                if !routes::configure(&utun_name, addr, prefix, mtu) {
                    error!("tunnel interface configuration failed; disabling tunnel");
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
            }
            Err(e) => {
                error!(%e, "handshake failed; re-dialing");
                continue;
            }
        }

        match pump(utun.clone(), &mut transport, shared.clone()).await {
            PumpEnd::Reconnect => {
                info!("transport ended; re-dialing");
            }
            PumpEnd::Fatal(e) => {
                error!(%e, "pump fatal");
                return Err(e);
            }
        }

        // Any pump end deactivates routing immediately, including transport
        // loss while user intent remains enabled. A later re-dial must complete
        // a fresh handshake and route transaction before becoming active again.
        shared.active.store(false, Ordering::Relaxed);
        info!("transport inactive; restoring routes");
        routes::teardown(
            &shared.utun_name,
            opts.server.ip(),
            &shared.wired_iface,
            &shared.wifi_iface,
        );
    }
}

/// Client handshake: send `Hello`, wait for the server's `Assign`.
async fn handshake(
    transport: &mut Transport,
) -> Result<(Ipv4Addr, u8, u16), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64);
    transport.send_frame(&Frame::Hello { client_nonce: nonce });
    loop {
        match transport.recv_control().await {
            Some((_, Frame::Assign { addr, prefix, mtu })) => {
                return Ok((addr, prefix, mtu));
            }
            Some((path, frame)) => {
                info!(path = %path.label(), ?frame, "control frame during handshake");
            }
            None => return Err("transport closed during handshake".into()),
        }
    }
}

/// How the pump exited.
enum PumpEnd {
    /// Transport fully closed (both paths) — re-dial.
    Reconnect,
    /// Fatal daemon error.
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

/// The packet pump: utun <-> transport.
///
///   * utun-reader task -> mpsc channel -> `send_data(seq, packet)` (scheduler
///     picks the live path)
///   * `recv_data` (deduped) -> write packet to utun (when enabled)
///   * every 500ms: republish the path snapshot and re-dial dead paths
///
/// Reconnect is driven by `is_alive()` polling (the transport's reader marks a
/// path dead when it errors) rather than `recv_dead`, because the receive
/// methods take `&mut self` and can't be armed alongside `recv_data`.
async fn pump(
    utun: Arc<AsyncFd<utun::Utun>>,
    transport: &mut Transport,
    shared: Arc<Shared>,
) -> PumpEnd {
    // The utun reader needs its own seq counter per outbound packet; the pump
    // owns it here alongside the transport.
    let mut seq = 0u64;
    let mut wbuf = vec![0u8; TUNNEL_MTU as usize + 4];
    let mut backoff = [Instant::now(); 2];

    let (tx_q, mut rx_q) = mpsc::channel::<Bytes>(256);
    spawn_utun_reader(utun.clone(), tx_q);

    let mut tick = tokio::time::interval(RECONNECT_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            Some(pkt) = rx_q.recv() => {
                if shared.enabled.load(Ordering::Relaxed) {
                    seq += 1;
                    transport.send_data(seq, pkt.clone());
                    shared.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                }
            }
            d = transport.recv_data() => {
                let d = match d {
                    Some(d) => d,
                    None => return PumpEnd::Reconnect,
                };
                update_active(&shared, d.path);
                shared.rx_bytes.fetch_add(d.packet.len() as u64, Ordering::Relaxed);
                if shared.enabled.load(Ordering::Relaxed)
                    && let Err(e) = utun.get_ref().write_packet(&mut wbuf, &d.packet)
                {
                    warn!(%e, "utun write error");
                }
            }
            _ = tick.tick() => {
                // A disconnect clears `enabled`; exit the pump so the control
                // loop can tear down routes and go idle.
                if !shared.enabled.load(Ordering::Relaxed) {
                    return PumpEnd::Reconnect;
                }
                publish_status(transport, &shared);
                reconnect_dead(transport, &shared, &mut backoff).await;
            }
        }
    }
}

/// Republish the path-liveness snapshot for the IPC server.
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

/// Re-dial any path the transport reports dead, rate-limited per path.
async fn reconnect_dead(
    transport: &Transport,
    shared: &Shared,
    backoff: &mut [Instant; 2],
) {
    for kind in PathKind::ALL {
        if transport.is_alive(kind) {
            continue;
        }
        let idx = match kind {
            PathKind::Wired => 0,
            PathKind::Wifi => 1,
        };
        if backoff[idx].elapsed() < RECONNECT_BACKOFF {
            continue;
        }
        backoff[idx] = Instant::now();
        let src = match kind {
            PathKind::Wired => shared.wired_src,
            PathKind::Wifi => shared.wifi_src,
        };
        match transport.reconnect_path(kind, shared.server, src).await {
            Ok(()) => info!(path = %kind.label(), "path re-dialed"),
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