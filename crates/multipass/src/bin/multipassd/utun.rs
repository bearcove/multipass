//! macOS utun device, created by hand via the kernel-control socket.
//!
//! macOS has no `/dev/net/tun`; the only way to get a userspace tunnel device
//! from a plain (non-extension) process is the kernel control socket:
//!
//!   1. `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` — one control socket.
//!   2. `ioctl(fd, CTLIOCGINFO, &ctl_info)` to resolve `UTUN_CONTROL_NAME`
//!      (`"com.apple.net.utun_control"`) to a kernel-control `ctl_id`.
//!   3. `connect(fd, sockaddr_ctl { sc_unit: 0, ... })` with `sc_unit = 0`
//!      (auto-assign). The kernel hands us the next free `utunN`; the assigned
//!      unit is read back via `getsockname`.
//!   4. The socket *is* the tunnel: `read`/`write` carry raw IP packets.
//!
//! # The 4-byte address-family header
//!
//! Every utun packet is prefixed with a 4-byte big-endian `u32` address
//! family (`AF_INET = 2` for IPv4). The kernel writes it on read and expects
//! it on write, so:
//!
//!   * **read**  — strip the leading 4 bytes, verify the family is `AF_INET`,
//!     and hand the remaining bytes (the raw IPv4 packet) onward.
//!   * **write** — prepend `2u32.to_be_bytes()` to the raw IPv4 packet.
//!
//! Non-`AF_INET` frames (e.g. `AF_INET6`, since the kernel may emit them even
//! with no configured v6) are dropped on read.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{
    AF_INET, AF_SYS_CONTROL, AF_SYSTEM, CTLIOCGINFO, SOCK_DGRAM, SYSPROTO_CONTROL, c_char, c_uchar,
    ctl_info, sockaddr, sockaddr_ctl,
};

/// Kernel control name for the utun subsystem.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

/// IPv4 address-family tag prepended to every utun frame (big-endian u32).
const AF_INET_TAG: u32 = AF_INET as u32;

/// An open utun device. `read_packet`/`write_packet` are blocking and expect
/// to be driven through `tokio::io::unix::AsyncFd` readiness.
pub struct Utun {
    fd: OwnedFd,
    unit: u32,
}

impl Utun {
    /// Open a fresh `utunN` (auto-assigned unit) via the kernel control socket.
    pub fn open() -> io::Result<Utun> {
        // 1. Control socket.
        let raw = unsafe { libc::socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        tracing::debug!(raw, "utun: socket()");
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // 2. Resolve UTUN_CONTROL_NAME -> ctl_id.
        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name = &UTUN_CONTROL_NAME[..UTUN_CONTROL_NAME.len().min(info.ctl_name.len())];
        for (dst, src) in info.ctl_name.iter_mut().zip(name.iter()) {
            *dst = *src as c_char;
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }
        tracing::debug!(ctl_id = info.ctl_id, "utun: CTLIOCGINFO");

        // 3. Connect, binding a SPECIFIC unit. We don't rely on reading the
        // assigned unit back (getsockname and the UTUN_IF_NAME ioctl are both
        // EOPNOTSUPP on macOS 27), so we ask for a known unit: sc_unit = N+1
        // yields interface `utunN`. Try a small range in case some are taken
        // by other VPNs / Continuity / etc.
        const FIRST_UNIT: u32 = 16; // pick high units to dodge system utun0..5
        const MAX_TRIES: u32 = 16;
        let mut connected_unit = None;
        for n in FIRST_UNIT..(FIRST_UNIT + MAX_TRIES) {
            let addr = sockaddr_ctl {
                sc_len: std::mem::size_of::<sockaddr_ctl>() as c_uchar,
                sc_family: AF_SYSTEM as c_uchar,
                ss_sysaddr: AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: n + 1, // unit N+1 => interface utunN
                sc_reserved: [0; 5],
            };
            let rc = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    &addr as *const sockaddr_ctl as *const sockaddr,
                    std::mem::size_of::<sockaddr_ctl>() as u32,
                )
            };
            if rc == 0 {
                connected_unit = Some(n);
                tracing::debug!(unit = n, "utun: connect() ok");
                break;
            }
            let e = io::Error::last_os_error();
            tracing::debug!(unit = n, err = %e, "utun: connect() unit busy, trying next");
        }
        let unit = connected_unit.ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrInUse, "no free utun unit in range")
        })?;

        Ok(Utun { fd, unit })
    }

    /// The interface name, e.g. `"utun3"`.
    pub fn name(&self) -> String {
        format!("utun{}", self.unit)
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Utun {
    /// Read one packet into `buf` (which must hold at least 4 bytes for the
    /// AF header). Strips the 4-byte AF header and validates it is `AF_INET`.
    /// Returns `Ok(Some(len))` with `buf[..len]` = the raw IPv4 packet, or
    /// `Ok(None)` when the frame was not IPv4 (dropped). `buf` is left alone
    /// on `Err`.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let n = unsafe { libc::read(self.fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Ok(None); // too short even for the AF header
        }
        let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if af != AF_INET_TAG {
            return Ok(None); // not IPv4, drop
        }
        let payload = n - 4;
        buf.copy_within(4..n, 0);
        Ok(Some(payload))
    }

    /// Write one raw IPv4 packet, prepending the 4-byte AF header. `buf` must
    /// be at least `payload.len() + 4`. Returns the payload byte count written.
    pub fn write_packet(&self, buf: &mut [u8], payload: &[u8]) -> io::Result<usize> {
        let total = 4 + payload.len();
        if buf.len() < total {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write buffer too small for AF header + payload",
            ));
        }
        buf[0..4].copy_from_slice(&AF_INET_TAG.to_be_bytes());
        buf[4..total].copy_from_slice(payload);
        let n = unsafe { libc::write(self.fd(), buf.as_ptr() as *const _, total) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((n as usize).saturating_sub(4))
    }
}

/// Look up the IPv4 address of `name` (e.g. `"en0"`), if it has one.
///
/// Used to pin the server's underlay host route to a physical interface's
/// own address (on-link next hop).
pub fn ipv4_for_iface(name: &str) -> Option<std::net::Ipv4Addr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut out = None;
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let ifa_name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        if ifa_name == name && !ifa.ifa_addr.is_null() {
            let sa = unsafe { &*ifa.ifa_addr };
            if sa.sa_family as i32 == libc::AF_INET {
                #[allow(clippy::cast_ptr_alignment)]
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                out = Some(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                break;
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

/// Map an IPv4 address back to the interface name that owns it.
pub fn iface_for_ip(ip: std::net::Ipv4Addr) -> Option<String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut out = None;
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            let sa = unsafe { &*ifa.ifa_addr };
            if sa.sa_family as i32 == libc::AF_INET {
                #[allow(clippy::cast_ptr_alignment)]
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let addr = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if addr == ip {
                    let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
                    out = Some(name.into_owned());
                    break;
                }
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    out
}
