//! Full-tunnel routing. Two jobs, in order:
//!
//! 1. **Pin the server's underlay address outside the tunnel.** Once the
//!    default route points through the utun, the tunnel's *own* QUIC packets
//!    (to the server's real IP) would otherwise recurse into the tunnel. We
//!    add a `-host` route for the server IP via each physical interface
//!    (`route -n add -host <server> -ifscope <iface> <iface-ip>`), keyed with
//!    `-ifscope` so the two per-interface routes coexist and the kernel picks
//!    the one matching the source-bound socket. This is the mullvad/wireguard
//!    incantation; it assumes the server is on-link (correct for a desk LAN).
//! 2. **Install the new default via the utun** (`route -n add -interface
//!    utunN default`) — the full-tunnel switch.
//!
//! `teardown` reverses both, restoring normal routing when the tunnel is
//! disconnected. Interface IP/MTU/up is configured with `ifconfig`.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

/// Compute the dotted netmask for a prefix length (e.g. /24 -> 255.255.255.0).
pub fn netmask_from_prefix(prefix: u8) -> Ipv4Addr {
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

/// `ifconfig utunN inet <addr> <peer> netmask <mask> mtu <mtu> up`.
/// For a point-to-point utun the second address is the tunnel peer (.1).
pub fn configure(utun: &str, addr: Ipv4Addr, prefix: u8, mtu: u16) -> bool {
    let netmask = netmask_from_prefix(prefix);
    let ok = run(
        "ifconfig",
        &[
            utun,
            "inet",
            &addr.to_string(),
            &multipass_proto::TUNNEL_SERVER.to_string(),
            "netmask",
            &netmask.to_string(),
            "mtu",
            &mtu.to_string(),
            "up",
        ],
    );
    if !ok {
        tracing::error!(utun, %addr, %netmask, mtu, "ifconfig failed");
    }
    ok
}

/// Install full-tunnel routing (host-route pins first, then default via utun).
pub fn setup(utun: &str, server: IpAddr, wired_if: &str, wifi_if: &str) {
    for iface in [wired_if, wifi_if] {
        if iface.is_empty() {
            continue;
        }
        match crate::utun::ipv4_for_iface(iface) {
            Some(addr) => {
                run(
                    "route",
                    &["-n", "add", "-host", &server.to_string(), "-ifscope", iface, &addr.to_string()],
                );
            }
            None => tracing::warn!(iface, "no ipv4 for interface; skipping server-route pin"),
        }
    }
    run("route", &["-n", "add", "-interface", utun, "default"]);
}

/// Reverse `setup`: restore normal routing.
pub fn teardown(utun: &str, server: IpAddr, wired_if: &str, wifi_if: &str) {
    run("route", &["-n", "delete", "-interface", utun, "default"]);
    for iface in [wired_if, wifi_if] {
        if iface.is_empty() {
            continue;
        }
        if let Some(addr) = crate::utun::ipv4_for_iface(iface) {
            run(
                "route",
                &["-n", "delete", "-host", &server.to_string(), "-ifscope", iface, &addr.to_string()],
            );
        }
    }
}

/// Run a command, logging on failure. Returns success.
fn run(prog: &str, args: &[&str]) -> bool {
    match Command::new(prog).args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            tracing::warn!(prog, args = ?args, %err, "command failed");
            false
        }
        Err(e) => {
            tracing::warn!(prog, args = ?args, %e, "command failed");
            false
        }
    }
}