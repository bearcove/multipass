//! Linux production-path tunnel client for isolated local benchmarks.
//!
//! This deliberately reuses `multipass::Transport` and the production wire
//! protocol. It differs from `multipassd` only at the OS tunnel boundary: a
//! Linux TUN replaces macOS utun, and no host routes are changed.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("multipass-linux-client is Linux-only");
}

#[cfg(target_os = "linux")]
mod linux {

    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use libc::{
        AF_INET, IFF_NOARP, IFF_POINTOPOINT, IFF_RUNNING, IFF_UP, IFNAMSIZ, SIOCGIFFLAGS,
        SIOCSIFADDR, SIOCSIFFLAGS, SIOCSIFMTU, SIOCSIFNETMASK, SOCK_DGRAM, c_char, c_int, c_short,
        c_ulong, in_addr, sockaddr, sockaddr_in,
    };
    use multipass::config::ClientConfigFile;
    use multipass::identity::client_config;
    use multipass::{ClientId, PathId, Transport, UplinkDial, transport_config};
    use multipass_proto::{Frame, TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_PREFIX};
    use tokio::sync::mpsc;
    use tracing::{info, warn};

    const TUNSETIFF: c_ulong = 0x4004_54ca;
    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;
    const CHANNEL_CAPACITY: usize = 4096;

    struct Tun {
        fd: OwnedFd,
        name: String,
    }

    impl Tun {
        fn open(ipv6: Option<(Ipv6Addr, u8)>) -> io::Result<Self> {
            let raw =
                unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
            ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
            if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut ifr) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let name = ifr_name(&ifr);
            configure(&name, ipv6)?;
            Ok(Self { fd, name })
        }
    }

    fn configure(name: &str, ipv6: Option<(Ipv6Addr, u8)>) -> io::Result<()> {
        let raw = unsafe { libc::socket(AF_INET, SOCK_DGRAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = unsafe { OwnedFd::from_raw_fd(raw) };
        with_ifr(sock.as_raw_fd(), SIOCSIFADDR, name, |ifr| {
            ifr.ifr_ifru.ifru_addr = sockaddr_in_to_sockaddr(sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: u32::from(TUNNEL_CLIENT).to_be(),
                },
                sin_zero: [0; 8],
            });
        })?;
        with_ifr(sock.as_raw_fd(), SIOCSIFNETMASK, name, |ifr| {
            ifr.ifr_ifru.ifru_addr = sockaddr_in_to_sockaddr(sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: in_addr {
                    s_addr: 0xff_ff_ff_00u32.to_be(),
                },
                sin_zero: [0; 8],
            });
        })?;
        with_ifr(sock.as_raw_fd(), SIOCSIFMTU, name, |ifr| {
            ifr.ifr_ifru.ifru_mtu = TUNNEL_MTU as c_int;
        })?;
        let mut flags = {
            let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
            set_name(&mut ifr, name);
            if unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut ifr) } < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { ifr.ifr_ifru.ifru_flags }
        };
        flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_NOARP) as c_short;
        with_ifr(sock.as_raw_fd(), SIOCSIFFLAGS, name, |ifr| {
            ifr.ifr_ifru.ifru_flags = flags;
        })?;
        if let Some((address, prefix)) = ipv6 {
            let output = std::process::Command::new("ip")
                .args([
                    "-6",
                    "addr",
                    "add",
                    &format!("{address}/{prefix}"),
                    "dev",
                    name,
                ])
                .output()?;
            if !output.status.success()
                && !String::from_utf8_lossy(&output.stderr).contains("File exists")
            {
                return Err(io::Error::other(
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
        }
        Ok(())
    }

    fn with_ifr(
        fd: c_int,
        request: c_ulong,
        name: &str,
        fill: impl FnOnce(&mut libc::ifreq),
    ) -> io::Result<()> {
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        set_name(&mut ifr, name);
        fill(&mut ifr);
        if unsafe { libc::ioctl(fd, request, &mut ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_name(ifr: &mut libc::ifreq, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(IFNAMSIZ - 1);
        for (slot, byte) in ifr.ifr_name[..len].iter_mut().zip(&bytes[..len]) {
            *slot = *byte as c_char;
        }
        ifr.ifr_name[len] = 0;
    }

    fn ifr_name(ifr: &libc::ifreq) -> String {
        let len = ifr
            .ifr_name
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(IFNAMSIZ);
        String::from_utf8_lossy(
            &ifr.ifr_name[..len]
                .iter()
                .map(|value| *value as u8)
                .collect::<Vec<_>>(),
        )
        .into_owned()
    }

    fn sockaddr_in_to_sockaddr(value: sockaddr_in) -> sockaddr {
        unsafe { mem::transmute(value) }
    }

    fn spawn_tun_reader(tun: Arc<Tun>, tx: mpsc::Sender<Bytes>) {
        std::thread::spawn(move || {
            let mut buffer = vec![0u8; TUNNEL_MTU as usize];
            loop {
                let read = unsafe {
                    libc::read(tun.fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())
                };
                if read < 0 {
                    warn!(error = %io::Error::last_os_error(), "TUN read failed");
                    break;
                }
                if read == 0
                    || tx
                        .blocking_send(Bytes::copy_from_slice(&buffer[..read as usize]))
                        .is_err()
                {
                    break;
                }
            }
        });
    }

    fn spawn_tun_writer(tun: Arc<Tun>, mut rx: mpsc::Receiver<Bytes>) {
        std::thread::spawn(move || {
            while let Some(packet) = rx.blocking_recv() {
                let mut remaining = &packet[..];
                while !remaining.is_empty() {
                    let written = unsafe {
                        libc::write(
                            tun.fd.as_raw_fd(),
                            remaining.as_ptr().cast(),
                            remaining.len(),
                        )
                    };
                    if written < 0 {
                        warn!(error = %io::Error::last_os_error(), "TUN write failed");
                        return;
                    }
                    remaining = &remaining[written as usize..];
                }
            }
        });
    }

    async fn await_assign(
        transport: &Transport,
        client_id: &ClientId,
        client_epoch: u64,
    ) -> Result<Option<(Ipv6Addr, u8)>, String> {
        for path_id in transport.path_ids() {
            let status = transport
                .path_status(path_id)
                .ok_or_else(|| format!("registered path {} disappeared", path_id.get()))?;
            transport.send_frame_on(
                path_id,
                &Frame::Hello {
                    client_id: client_id.clone(),
                    client_epoch,
                    uplink_id: status.uplink_id,
                    path_id,
                    connection_generation: 0,
                },
            );
        }
        let mut ipv6 = None;
        let mut assigned_server_version = None;
        while transport
            .path_ids()
            .any(|path_id| !transport.is_ready(path_id))
        {
            let Some((path_id, frame)) = transport.recv_control().await else {
                return Err("transport closed before assignment".into());
            };
            if let Frame::Assign {
                ipv4,
                ipv6: assigned_ipv6,
                mtu,
                server_version,
                ..
            } = frame
            {
                if ipv4 != Some((TUNNEL_CLIENT, TUNNEL_PREFIX)) || mtu != TUNNEL_MTU {
                    return Err("server assignment does not match tunnel contract".into());
                }
                if let Some(assigned) = &assigned_server_version {
                    if assigned != &server_version {
                        return Err("paths reported different server build identities".into());
                    }
                } else {
                    assigned_server_version = Some(server_version.clone());
                }
                if ipv6.is_none() {
                    ipv6 = assigned_ipv6;
                }
                let status = transport.path_status(path_id).ok_or_else(|| {
                    format!("assignment arrived on unknown path {}", path_id.get())
                })?;
                transport.mark_ready(path_id);
                info!(
                    path_id = path_id.get(),
                    uplink = %status.uplink_id,
                    %server_version,
                    "path assigned"
                );
            }
        }
        Ok(ipv6)
    }

    #[tokio::main]
    pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    "multipass_linux_client=info,multipass=info,noq=warn"
                        .parse()
                        .unwrap()
                }),
            )
            .init();

        let args = std::env::args().collect::<Vec<_>>();
        if args.len() != 4 {
            return Err(format!(
                "usage: {} <config.json> <source-ip> <client-epoch>",
                args[0]
            )
            .into());
        }
        let runtime = ClientConfigFile::load_validated_runtime(&args[1])?;
        let config = &runtime.config;
        let source = args[2].parse::<IpAddr>()?;
        let client_epoch = args[3].parse::<u64>()?;
        let server = config
            .gateway
            .endpoints
            .first()
            .ok_or_else(|| io::Error::other("validated config has no gateway endpoint"))?
            .address;
        let uplink = config
            .uplinks
            .iter()
            .find(|uplink| uplink.enabled)
            .ok_or_else(|| io::Error::other("config has no enabled uplink"))?;
        let client_id = config.client.id.clone();
        let quic_config = client_config(
            &runtime.identity,
            config.gateway.server_public_key,
            transport_config(),
        )?;
        let transport = Transport::connect_with_client_config(
            server,
            vec![UplinkDial {
                path_id: PathId::new(1),
                uplink_id: uplink.id.clone(),
                source,
            }],
            quic_config,
        )
        .await?;
        let ipv6 = await_assign(&transport, &client_id, client_epoch)
            .await
            .map_err(io::Error::other)?;
        let tun = Arc::new(Tun::open(ipv6)?);
        info!(interface = %tun.name, "local benchmark tunnel ready");

        let (from_tun_tx, mut from_tun_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (to_tun_tx, to_tun_rx) = mpsc::channel(CHANNEL_CAPACITY);
        spawn_tun_reader(tun.clone(), from_tun_tx);
        spawn_tun_writer(tun, to_tun_rx);

        let sequence = AtomicU64::new(1);
        let mut sack_tick = tokio::time::interval(Duration::from_millis(10));
        sack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(packet) = from_tun_rx.recv() => {
                    let seq = sequence.fetch_add(1, Ordering::Relaxed);
                    transport.send_data(seq, packet);
                }
                packet = transport.recv_data() => {
                    let Some(packet) = packet else { break };
                    if to_tun_tx.send(packet.packet).await.is_err() { break; }
                }
                control = transport.recv_control() => {
                    if control.is_none() { break; }
                }
                dead = transport.recv_dead() => {
                    if let Some(status) = transport.path_status(dead) {
                        warn!(path_id = dead.get(), uplink = %status.uplink_id, "local benchmark path died");
                    } else {
                        warn!(path_id = dead.get(), "unknown local benchmark path died");
                    }
                }
                _ = sack_tick.tick() => transport.broadcast_sack(),
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run()
}
