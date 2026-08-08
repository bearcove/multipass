//! multipassd — the privileged multipass client daemon (macOS, root).
//!
//! Owns the tunnel: creates a utun device, assigns the tunnel IP + MTU,
//! installs full-tunnel routing, and pumps raw IP packets between the utun
//! and the dual-connection active-active failover transport.
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

mod ipc;
mod routes;
mod transport;
mod utun;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use multipass_proto::{Frame, TUNNEL_CLIENT, TUNNEL_MTU};
use tokio::io::unix::AsyncFd;
use tracing::{error, info, warn};

use transport::{Data, PathKind, Transport};

/// Live daemon state shared between the pump and the IPC server. The
/// `transport` is swapped on reconnect (hence `RwLock<Option<…>>`).
pub struct Shared {
    pub transport: RwLock<Option<Arc<Transport>>>,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub enabled: AtomicBool,
    pub active_path: RwLock<Option<PathKind>>,
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
            transport: RwLock::new(None),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            active_path: RwLock::new(None),
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let utun = Arc::new(AsyncFd::new(utun::Utun::open()?)?);
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

    // Transport lifecycle: connect, handshake, pump; re-dial on any end.
    loop {
        let transport = match Transport::connect(opts.server, opts.wired, opts.wifi).await {
            Ok(t) => t,
            Err(e) => {
                warn!(%e, "transport connect failed; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let transport = Arc::new(transport);
        *shared.transport.write().unwrap() = Some(transport.clone());

        match handshake(&transport).await {
            Ok((addr, prefix, mtu)) => {
                info!(%addr, prefix, mtu, "assigned; configuring tunnel");
                let utun_name = shared.utun_name.clone();
                routes::configure(&utun_name, addr, prefix, mtu);
                routes::setup(
                    &utun_name,
                    opts.server.ip(),
                    &shared.wired_iface,
                    &shared.wifi_iface,
                );
                shared.enabled.store(true, Ordering::Relaxed);
            }
            Err(e) => {
                error!(%e, "handshake failed; re-dialing");
                continue;
            }
        }

        match pump(utun.clone(), transport, shared.clone()).await {
            PumpEnd::Reconnect => {
                info!("transport ended; re-dialing");
                shared.enabled.store(false, Ordering::Relaxed);
            }
            PumpEnd::Fatal(e) => {
                error!(%e, "pump fatal");
                return Err(e);
            }
        }
    }
}

/// Client handshake: send `Hello`, wait for the server's `Assign`.
async fn handshake(
    transport: &Transport,
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
            Some((kind, frame)) => {
                info!(path = %kind.label(), ?frame, "control frame during handshake");
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

/// The packet pump: utun <-> transport, with per-path status and reconnect.
///
///   * utun read  -> `Frame::Data { seq, packet }` -> `send_data` on both conns
///   * conn read  -> deduped `Data` -> write packet to utun (when enabled)
///   * path dead  -> `reconnect_path` re-dials just that path
async fn pump(
    utun: Arc<AsyncFd<utun::Utun>>,
    transport: Arc<Transport>,
    shared: Arc<Shared>,
) -> PumpEnd {
    let mut seq = 0u64;
    let mut rbuf = vec![0u8; TUNNEL_MTU as usize + 4];
    let mut wbuf = vec![0u8; TUNNEL_MTU as usize + 4];

    loop {
        tokio::select! {
            res = utun.readable() => {
                match res {
                    Ok(mut guard) => {
                        match guard.get_inner().read_packet(&mut rbuf) {
                            Ok(Some(n)) => {
                                let pkt = Bytes::copy_from_slice(&rbuf[..n]);
                                seq += 1;
                                transport.send_data(seq, pkt.clone());
                                shared.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
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
                    Err(e) => return PumpEnd::Fatal(Box::new(e)),
                }
            }
            data = transport.recv_data() => {
                match data {
                    Some(Data { packet, path, .. }) => {
                        *shared.active_path.write().unwrap() = Some(path);
                        shared.rx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                        if shared.enabled.load(Ordering::Relaxed) {
                            if let Err(e) = guardless_write(&utun, &mut wbuf, &packet) {
                                warn!(%e, "utun write error");
                            }
                        }
                    }
                    None => return PumpEnd::Reconnect,
                }
            }
            kind = transport.recv_dead() => {
                warn!(path = %kind.label(), "path lost; re-dialing");
                let src = match kind {
                    PathKind::Wired => shared.wired_src,
                    PathKind::Wifi => shared.wifi_src,
                };
                match transport.reconnect_path(kind, shared.server, src).await {
                    Ok(()) => info!(path = %kind.label(), "path re-dialed"),
                    Err(e) => warn!(path = %kind.label(), %e, "path re-dial failed"),
                }
            }
        }
    }
}

/// Write a packet to the utun synchronously (fast path; utun never blocks on
/// write at desk scale). Returns the payload bytes written.
fn guardless_write(utun: &AsyncFd<utun::Utun>, wbuf: &mut [u8], packet: &[u8]) -> io::Result<usize> {
    utun.get_ref().write_packet(wbuf, packet)
}

/// Extract the IPv4 address from an `IpAddr` (we only tunnel IPv4).
fn source_ipv4(ip: &IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(_) => None,
    }
}