//! Tunnel/default-route ownership and endpoint-specific underlay routes.
//!
//! `setup`/`teardown` retain the existing tunnel interface and half-default
//! ownership. Their pin list is dynamic so callers are not limited to a fixed
//! wired/Wi-Fi pair. New roaming candidates use `install_underlay_route` and
//! `remove_underlay_route`; their reference-counted ownership lives in
//! `underlay.rs`.

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

/// Install full-tunnel routing transactionally: all supplied endpoint pins
/// first, then two more-specific half-default routes via utun. Any failure
/// removes every route installed so far without touching the physical default.
pub fn setup(utun: &str, server: IpAddr, interfaces: &[&str]) -> bool {
    let pins = interfaces
        .iter()
        .copied()
        .filter(|interface| !interface.is_empty())
        .map(|interface| crate::utun::ipv4_for_iface(interface).map(|addr| (interface, addr)))
        .collect::<Option<Vec<_>>>();
    let Some(pins) = pins else {
        tracing::error!("an interface has no IPv4 address; cannot pin server route");
        return false;
    };
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
pub fn teardown(utun: &str, server: IpAddr, interfaces: &[&str]) {
    let pins = interfaces
        .iter()
        .copied()
        .filter(|interface| !interface.is_empty())
        .filter_map(|interface| {
            crate::utun::ipv4_for_iface(interface).map(|address| (interface, address))
        })
        .collect::<Vec<_>>();
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

/// Install one endpoint-specific scoped host route from a native service
/// resolution. The service router is the gateway for off-link endpoints;
/// on-link endpoints use the interface/source form.
pub fn install_underlay_route(route: &crate::underlay::UnderlayRoute) -> bool {
    mutate_underlay_route("add", route, run)
}

/// Remove exactly the scoped host route installed for a candidate.
pub fn remove_underlay_route(route: &crate::underlay::UnderlayRoute) -> bool {
    mutate_underlay_route("delete", route, run)
}

fn mutate_underlay_route<F>(
    operation: &str,
    route: &crate::underlay::UnderlayRoute,
    mut run_command: F,
) -> bool
where
    F: FnMut(&str, &[&str]) -> bool,
{
    let endpoint = route.endpoint.to_string();
    let source = route.source.to_string();
    let next_hop = route.next_hop.map(|address| {
        if matches!(address, IpAddr::V6(address) if address.is_unicast_link_local()) {
            let scope = route
                .interface_scope
                .as_deref()
                .unwrap_or(route.interface.as_str());
            format!("{address}%{scope}")
        } else {
            address.to_string()
        }
    });
    let family = match route.family {
        crate::underlay::AddressFamily::Ipv4 => None,
        crate::underlay::AddressFamily::Ipv6 => Some("-inet6"),
    };
    let gateway = next_hop.as_deref().unwrap_or(source.as_str());
    let mut args = Vec::with_capacity(8);
    args.extend(["-n", operation]);
    if let Some(family) = family {
        args.push(family);
    }
    args.extend([
        "-host",
        endpoint.as_str(),
        "-ifscope",
        route.interface.as_str(),
    ]);
    if route.next_hop.is_none() {
        args.push("-interface");
    }
    args.push(gateway);
    run_command("route", &args)
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

/// Install the IPv6 half-default routes into the tunnel. Rolls back on
/// failure without replacing the physical default.
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

    use crate::underlay::{AddressFamily, UnderlayRoute};

    use super::{
        default_route_args, mutate_underlay_route, setup_with, teardown_with, v6_default_route_args,
    };

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
                ("en17", Ipv4Addr::new(10, 10, 10, 171)),
                ("en0", Ipv4Addr::new(10, 10, 10, 169)),
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
                ("en17", Ipv4Addr::new(10, 10, 10, 171)),
                ("en0", Ipv4Addr::new(10, 10, 10, 169)),
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
    fn tunnel_setup_accepts_dynamic_interface_count() {
        let pins = [
            ("en0", Ipv4Addr::new(10, 0, 0, 2)),
            ("en7", Ipv4Addr::new(10, 1, 0, 2)),
            ("en9", Ipv4Addr::new(10, 2, 0, 2)),
        ];
        let mut calls = Vec::new();
        assert!(setup_with(
            "utun16",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            &pins,
            |_, args| {
                calls.push(args.iter().map(ToString::to_string).collect::<Vec<_>>());
                true
            },
        ));
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0][5], "en0");
        assert_eq!(calls[1][5], "en7");
        assert_eq!(calls[2][5], "en9");
    }

    #[test]
    fn underlay_route_commands_scope_ipv4_and_ipv6() {
        let mut calls = Vec::new();
        let v4 = UnderlayRoute {
            endpoint: "203.0.113.9".parse().unwrap(),
            interface: "en7".to_owned(),
            source: "10.20.30.40".parse().unwrap(),
            next_hop: Some("10.20.30.1".parse().unwrap()),
            family: AddressFamily::Ipv4,
            interface_scope: None,
            network_generation: 1,
        };
        let v6 = UnderlayRoute {
            endpoint: "2001:db8:ffff::9".parse().unwrap(),
            interface: "en0".to_owned(),
            source: "2001:db8:1::23".parse().unwrap(),
            next_hop: Some("fe80::1".parse().unwrap()),
            family: AddressFamily::Ipv6,
            interface_scope: Some("en0".to_owned()),
            network_generation: 1,
        };
        assert!(mutate_underlay_route("add", &v4, |program, args| {
            calls.push((
                program.to_owned(),
                args.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ));
            true
        }));
        assert!(mutate_underlay_route("delete", &v6, |program, args| {
            calls.push((
                program.to_owned(),
                args.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ));
            true
        }));
        assert_eq!(
            calls[0].1,
            [
                "-n",
                "add",
                "-host",
                "203.0.113.9",
                "-ifscope",
                "en7",
                "10.20.30.1",
            ]
        );
        assert_eq!(
            calls[1].1,
            [
                "-n",
                "delete",
                "-inet6",
                "-host",
                "2001:db8:ffff::9",
                "-ifscope",
                "en0",
                "fe80::1%en0",
            ]
        );
    }

    #[test]
    fn on_link_underlay_route_uses_interface_source() {
        let route = UnderlayRoute {
            endpoint: "192.168.1.90".parse().unwrap(),
            interface: "en0".to_owned(),
            source: "192.168.1.23".parse().unwrap(),
            next_hop: None,
            family: AddressFamily::Ipv4,
            interface_scope: None,
            network_generation: 1,
        };
        let mut args = Vec::new();
        assert!(mutate_underlay_route("add", &route, |_, command_args| {
            args = command_args.iter().map(ToString::to_string).collect();
            true
        }));
        assert_eq!(
            args,
            [
                "-n",
                "add",
                "-host",
                "192.168.1.90",
                "-ifscope",
                "en0",
                "-interface",
                "192.168.1.23",
            ]
        );
    }

    #[test]
    fn pin_failure_rolls_back_prior_pin_without_installing_default() {
        let mut calls = Vec::new();
        let mut adds = 0;
        let ok = setup_with(
            "utun16",
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
            &[
                ("en17", Ipv4Addr::new(10, 10, 10, 171)),
                ("en0", Ipv4Addr::new(10, 10, 10, 169)),
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
