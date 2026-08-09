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

/// `ifconfig utunN inet6 <addr> prefixlen <prefix>` — assign the IPv6 tunnel
/// address. The utun already has MTU/up from the IPv4 configure.
pub fn configure_v6(utun: &str, addr: std::net::Ipv6Addr, prefix: u8) -> bool {
    let ok = run(
        "ifconfig",
        &[
            utun,
            "inet6",
            &addr.to_string(),
            "prefixlen",
            &prefix.to_string(),
        ],
    );
    if !ok {
        tracing::error!(utun, %addr, prefix, "ifconfig inet6 failed");
    }
    ok
}

/// Install full-tunnel routing transactionally: host-route pins first, then
/// two more-specific half-default routes via utun. Any failure removes every
/// route installed so far without touching the physical default route.
pub fn setup(utun: &str, server: IpAddr, wired_if: &str, wifi_if: &str) -> bool {
    let mut pins = Vec::with_capacity(2);
    for iface in [wired_if, wifi_if] {
        if iface.is_empty() {
            continue;
        }
        let Some(addr) = crate::utun::ipv4_for_iface(iface) else {
            tracing::error!(iface, "no ipv4 for interface; cannot pin server route");
            return false;
        };
        pins.push((iface, addr));
    }

    setup_with(utun, server, &pins, run)
}

fn setup_with<F>(utun: &str, server: IpAddr, pins: &[(&str, Ipv4Addr)], mut run_command: F) -> bool
where
    F: FnMut(&str, &[&str]) -> bool,
{
    let server = server.to_string();
    let mut installed_pins = Vec::with_capacity(pins.len());

    for &(iface, addr) in pins {
        let addr = addr.to_string();
        let args = [
            "-n",
            "add",
            "-host",
            server.as_str(),
            "-ifscope",
            iface,
            addr.as_str(),
        ];
        if !run_command("route", &args) {
            rollback_pins(&server, &installed_pins, &mut run_command);
            return false;
        }
        installed_pins.push((iface, addr));
    }

    let tunnel_routes = default_route_args(utun);
    for (index, args) in tunnel_routes.iter().enumerate() {
        if !run_command("route", args) {
            for installed in tunnel_routes[..index].iter().rev() {
                let delete = [
                    "-n",
                    "delete",
                    installed[2],
                    installed[3],
                    installed[4],
                    installed[5],
                ];
                run_command("route", &delete);
            }
            rollback_pins(&server, &installed_pins, &mut run_command);
            return false;
        }
    }

    true
}

fn rollback_pins<F>(server: &str, installed: &[(&str, String)], run_command: &mut F)
where
    F: FnMut(&str, &[&str]) -> bool,
{
    for (iface, addr) in installed.iter().rev() {
        let args = [
            "-n",
            "delete",
            "-host",
            server,
            "-ifscope",
            *iface,
            addr.as_str(),
        ];
        run_command("route", &args);
    }
}

/// Reverse `setup`, deleting only routes owned by this tunnel.
pub fn teardown(utun: &str, server: IpAddr, wired_if: &str, wifi_if: &str) {
    let mut pins = Vec::with_capacity(2);
    for iface in [wired_if, wifi_if] {
        if iface.is_empty() {
            continue;
        }
        if let Some(addr) = crate::utun::ipv4_for_iface(iface) {
            pins.push((iface, addr));
        }
    }
    teardown_with(utun, server, &pins, run);
}

fn teardown_with<F>(utun: &str, server: IpAddr, pins: &[(&str, Ipv4Addr)], mut run_command: F)
where
    F: FnMut(&str, &[&str]) -> bool,
{
    for installed in default_route_args(utun) {
        let args = [
            "-n",
            "delete",
            installed[2],
            installed[3],
            installed[4],
            installed[5],
        ];
        run_command("route", &args);
    }

    let server = server.to_string();
    for &(iface, addr) in pins {
        let addr = addr.to_string();
        run_command(
            "route",
            &[
                "-n",
                "delete",
                "-host",
                server.as_str(),
                "-ifscope",
                iface,
                addr.as_str(),
            ],
        );
    }
}

fn default_route_args(utun: &str) -> [[&str; 6]; 2] {
    [
        ["-n", "add", "-net", "0.0.0.0/1", "-interface", utun],
        ["-n", "add", "-net", "128.0.0.0/1", "-interface", utun],
    ]
}

/// IPv6 half-default routes into the tunnel (`::/1` + `8000::/1`). These win
/// longest-prefix over the physical default without replacing it, so teardown
/// never has to restore the original default.
fn v6_default_route_args(utun: &str) -> [[&str; 7]; 2] {
    [
        ["-n", "add", "-inet6", "-net", "::/1", "-interface", utun],
        [
            "-n",
            "add",
            "-inet6",
            "-net",
            "8000::/1",
            "-interface",
            utun,
        ],
    ]
}

/// Install the IPv6 half-default routes into the tunnel. No server-endpoint
/// pins are needed for IPv6 because the QUIC underlay remains IPv4; the only
/// v6 routes are the tunnel defaults. Rolls back on failure.
pub fn setup_v6(utun: &str) -> bool {
    let routes = v6_default_route_args(utun);
    for (index, args) in routes.iter().enumerate() {
        if !run("route", args) {
            for installed in routes[..index].iter().rev() {
                let delete = [
                    "-n",
                    "delete",
                    installed[2],
                    installed[3],
                    installed[4],
                    installed[5],
                    installed[6],
                ];
                run("route", &delete);
            }
            return false;
        }
    }
    true
}

/// Remove the IPv6 half-default routes installed by `setup_v6`.
pub fn teardown_v6(utun: &str) {
    for installed in v6_default_route_args(utun) {
        let delete = [
            "-n",
            "delete",
            installed[2],
            installed[3],
            installed[4],
            installed[5],
            installed[6],
        ];
        run("route", &delete);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{default_route_args, setup_with, teardown_with, v6_default_route_args};

    #[test]
    fn tunnel_routes_preserve_physical_default() {
        assert_eq!(
            default_route_args("utun16"),
            [
                ["-n", "add", "-net", "0.0.0.0/1", "-interface", "utun16"],
                ["-n", "add", "-net", "128.0.0.0/1", "-interface", "utun16"],
            ]
        );
    }

    #[test]
    fn v6_tunnel_routes_preserve_physical_default() {
        assert_eq!(
            v6_default_route_args("utun16"),
            [
                [
                    "-n",
                    "add",
                    "-inet6",
                    "-net",
                    "::/1",
                    "-interface",
                    "utun16"
                ],
                [
                    "-n",
                    "add",
                    "-inet6",
                    "-net",
                    "8000::/1",
                    "-interface",
                    "utun16"
                ],
            ]
        );
    }

    #[test]
    fn teardown_deletes_only_tunnel_owned_routes() {
        let mut calls = Vec::new();
        teardown_with(
            "utun16",
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
            &[
                (&"en17", Ipv4Addr::new(10, 10, 10, 171)),
                (&"en0", Ipv4Addr::new(10, 10, 10, 169)),
            ],
            |prog, args| {
                calls.push((
                    prog.to_string(),
                    args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>(),
                ));
                true
            },
        );

        assert_eq!(
            calls[0].1,
            ["-n", "delete", "-net", "0.0.0.0/1", "-interface", "utun16"]
        );
        assert_eq!(
            calls[1].1,
            [
                "-n",
                "delete",
                "-net",
                "128.0.0.0/1",
                "-interface",
                "utun16"
            ]
        );
        assert!(
            !calls
                .iter()
                .any(|(_, args)| args == &["-n", "delete", "default", "-interface", "utun16"])
        );
    }

    #[test]
    fn second_tunnel_route_failure_rolls_back_first_route_and_pins() {
        let mut calls = Vec::new();
        let ok = setup_with(
            "utun16",
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
            &[
                (&"en17", Ipv4Addr::new(10, 10, 10, 171)),
                (&"en0", Ipv4Addr::new(10, 10, 10, 169)),
            ],
            |prog, args| {
                calls.push((
                    prog.to_string(),
                    args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>(),
                ));
                !args.contains(&"128.0.0.0/1")
            },
        );

        assert!(!ok);
        assert_eq!(calls.len(), 7);
        assert_eq!(
            calls[4].1,
            ["-n", "delete", "-net", "0.0.0.0/1", "-interface", "utun16"]
        );
        assert_eq!(calls[5].1[5], "en0");
        assert_eq!(calls[6].1[5], "en17");
    }

    #[test]
    fn pin_failure_rolls_back_prior_pin_without_installing_default() {
        let mut calls = Vec::new();
        let mut adds = 0;
        let ok = setup_with(
            "utun16",
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
            &[
                (&"en17", Ipv4Addr::new(10, 10, 10, 171)),
                (&"en0", Ipv4Addr::new(10, 10, 10, 169)),
            ],
            |prog, args| {
                calls.push((
                    prog.to_string(),
                    args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>(),
                ));
                if args.contains(&"add") {
                    adds += 1;
                    adds != 2
                } else {
                    true
                }
            },
        );

        assert!(!ok);
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].1[1], "delete");
        assert!(
            !calls
                .iter()
                .any(|(_, args)| args.contains(&"default".to_string()))
        );
    }
}
