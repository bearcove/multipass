//! Linux TUN device, hand-rolled against `/dev/net/tun` with `libc`.
//!
//! The server owns subnet 10.10.99.0/24: it creates the device, assigns
//! `TUNNEL_SERVER` (10.10.99.1), sets the MTU and brings the link up. No
//! external tooling (`ip`/`ifconfig`) is required — everything is ioctls.
//!
//! On non-Linux targets this module compiles to a stub that produces a
//! runtime error ("linux only"); the daemon refuses to start there.

#[cfg(target_os = "linux")]
mod imp {
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    AF_INET, IFNAMSIZ, IFF_NOARP, IFF_POINTOPOINT, IFF_RUNNING, IFF_UP, SIOCGIFFLAGS,
    SIOCSIFADDR, SIOCSIFMTU, SIOCSIFNETMASK, SIOCSIFFLAGS, SOCK_DGRAM, c_char, c_int, c_short,
    c_ulong, in_addr, sockaddr, sockaddr_in,
};

use multipass_proto::{TUNNEL_MTU, TUNNEL_SERVER};

/// `_IOW('T', 202, int)` — the TUNSETIFF request. Not exported by libc.
const TUNSETIFF: c_ulong = 0x4004_54ca;
/// Create a TUN (point-to-point layer 3) device.
const IFF_TUN: c_short = 0x0001;
/// Omit the 4-byte packet-info header on every read/write (raw IP packets).
const IFF_NO_PI: c_short = 0x1000;

/// A configured, up TUN device.
pub struct Tun {
    /// File descriptor used for reading/writing IP packets.
    pub fd: OwnedFd,
    /// Kernel-assigned interface name (e.g. `tun0`).
    pub name: String,
}

/// Create the device, assign `10.10.99.1/24`, set MTU, bring it up.
pub fn open() -> io::Result<Tun> {
    let fd = open_dev_net_tun()?;
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    // Empty name => kernel picks a free `tunN` and reports it back into ifr_name.
    ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
    // Pass a mutable pointer: the kernel writes the assigned name in place.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut ifr as *mut libc::ifreq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let name = ifr_name(&ifr);
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "TUNSETIFF returned an empty interface name",
        ));
    }
    configure(&name)?;
    Ok(Tun { fd, name })
}

fn open_dev_net_tun() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Assign address, netmask, MTU and bring the link up.
fn configure(name: &str) -> io::Result<()> {
    let sock = unsafe { libc::socket(AF_INET, SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };

    with_ifr(sock.as_raw_fd(), SIOCSIFADDR, name, |ifr| {
        ifr.ifr_ifru.ifru_addr = sockaddr_in_to_sockaddr(sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: in_addr { s_addr: u32::from(TUNNEL_SERVER).to_be() },
            sin_zero: [0; 8],
        });
    })?;

    // 10.10.99.0/24 => netmask 255.255.255.0.
    with_ifr(sock.as_raw_fd(), SIOCSIFNETMASK, name, |ifr| {
        ifr.ifr_ifru.ifru_addr = sockaddr_in_to_sockaddr(sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0xFF_FF_FF_00u32.to_be() },
            sin_zero: [0; 8],
        });
    })?;

    with_ifr(sock.as_raw_fd(), SIOCSIFMTU, name, |ifr| {
        ifr.ifr_ifru.ifru_mtu = TUNNEL_MTU as c_int;
    })?;

    // Read current flags, OR in UP|RUNNING, write back.
    let mut flags = {
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        set_name(&mut ifr, name);
        let rc = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe { ifr.ifr_ifru.ifru_flags }
    };
    flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_NOARP) as c_short;
    with_ifr(sock.as_raw_fd(), SIOCSIFFLAGS, name, |ifr| {
        ifr.ifr_ifru.ifru_flags = flags;
    })?;

    Ok(())
}

/// Run `ioctl(sock, req, &ifr)` with `ifr` initialized to `name`, then filled by `f`.
fn with_ifr(
    sock: c_int,
    req: c_ulong,
    name: &str,
    f: impl FnOnce(&mut libc::ifreq),
) -> io::Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_name(&mut ifr, name);
    f(&mut ifr);
    let rc = unsafe { libc::ioctl(sock, req, &ifr) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_name(ifr: &mut libc::ifreq, name: &str) {
    let bytes = name.as_bytes();
    let n = bytes.len().min(IFNAMSIZ - 1);
    for (slot, &b) in ifr.ifr_name[..n].iter_mut().zip(&bytes[..n]) {
        *slot = b as c_char;
    }
    ifr.ifr_name[n] = 0;
}

/// Read the NUL-terminated interface name back out of an ifreq.
fn ifr_name(ifr: &libc::ifreq) -> String {
    let end = ifr.ifr_name.iter().position(|&c| c == 0).unwrap_or(ifr.ifr_name.len());
    let name: Vec<u8> = ifr.ifr_name[..end].iter().map(|&c| c as u8).collect();
    String::from_utf8_lossy(&name).into_owned()
}

fn sockaddr_in_to_sockaddr(sa: sockaddr_in) -> sockaddr {
    // Both are 16 bytes: sin_family+sin_port+sin_addr+sin_zero == sa_family+sa_data.
    unsafe { mem::transmute(sa) }
}
} // mod imp

#[cfg(target_os = "linux")]
pub use imp::*;

/// Non-Linux: the TUN device only exists on Linux (router).
#[cfg(not(target_os = "linux"))]
pub mod imp {
    use std::io;
    pub struct Tun {
        pub fd: std::os::fd::OwnedFd,
        pub name: String,
    }
    pub fn open() -> io::Result<Tun> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "multipass-server is linux only"))
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::*;