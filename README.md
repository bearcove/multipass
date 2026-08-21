# multipass

Experimental N-uplink packet tunnel for a Mac that may have Ethernet, Wi-Fi,
tethering, or other configured underlays. Multipass aggregates available links
while preserving ordinary TCP, UDP, ICMP, IPv4, and IPv6 sessions as underlays
appear, disappear, or change address.

The macOS 27+ client and Linux router server work end to end today, including
dual-stack forwarding. Seamless failover and full aggregate throughput are not
yet proven; see [Status](#status) for measured results and the current blocker.

## Why this exists

At the desk, a MacBook may use wired Ethernet and Wi-Fi at the same time. Away
from home it may have only Wi-Fi or tethering. Binding an ordinary session to
one physical interface makes a cable unplug, address change, or endpoint change
visible to applications. Multipass keeps one stable logical tunnel while its
configured underlays change independently.

The off-the-shelf answer is **[mqvpn](https://github.com/mp0rta/mqvpn)** — a
multipath QUIC VPN that proved the concept for us. It is far more
feature-complete (Windows/Linux/Android, bandwidth aggregation, FEC, a hybrid
TCP lane, and a real control API). Multipass is a small Rust implementation of
the part we need on the noq / QUIC stack we already trust.

Plain **WireGuard + MPTCP** cannot provide the same macOS-wide property: MPTCP
is per-application opt-in through Network.framework, and WireGuard roaming can
still stall sessions during path changes. The continuity mechanism belongs at
the packet layer.

## Current scope

- One macOS client (`scooter`) and one Linux router/server (`jax`).
- Zero, one, or any configured number of underlay uplinks. An enabled client
  with no usable uplink remains enabled and waits for connectivity.
- One authenticated connection per ready uplink. Each uplink independently
  races compatible LAN IPv4, public IPv4, and public IPv6 gateway endpoints.
- Raw IPv4 and IPv6 packets through one stable dual-stack tunnel interface.
- Bidirectional bandwidth aggregation across all configured-enabled ready
  uplinks.
- Sequence-numbered packets, selective acknowledgements, retransmission, and
  receive-side deduplication.
- Exact pinned Ed25519 gateway identity plus mutually authenticated,
  server-authorized client identity. Endpoint addresses are not identities.
- IPv4 masquerading at the router. IPv6 uses a runtime-configured routed `/64`;
  deployment-specific prefixes remain outside this public repository.

Multi-client tunnel-address allocation and non-macOS production clients are
outside the current scope.

## How it works

- Root-owned JSON configuration lists the logical gateway, its pinned public
  key, its reachable endpoints, the persistent client-key path, and an ordered
  set of logical uplinks.
- For every enabled uplink, the daemon observes its configured interface,
  resolves usable native addresses and routes, and concurrently races all
  address-family-compatible gateway endpoints. The first mutually authenticated
  candidate wins for that uplink; alternate endpoints do not become extra
  scheduler capacity.
- At home, a LAN endpoint normally wins. Away from home, public IPv4 or IPv6 can
  win without an SSID rule, location detector, or identity change.
- A congestion-aware scheduler sends each tunnel packet on one ready uplink
  according to RTT and outgoing queue pressure.
- Every packet carries a sequence number and remains in a bounded send window
  until the peer's selective ACK confirms receipt. Missing sequences can be
  retransmitted on a surviving path; the receiver deduplicates them.
- Connection replacement preserves the logical epoch, tunnel addresses,
  sequence space, reliability windows, counters, and application sessions.
- The tunnel carries both IPv4 and IPv6 at MTU 1280. QUIC negotiates ALPN
  `multipass/4`, whose authenticated Hello binds a connection to the authorized
  client and stable uplink identity.

```text
   applications (ordinary IPv4 + IPv6 sockets)
                     |
                     v
              stable utun device
                     |
       logical session + SACK/send window
                     |
       +-------------+-------------+--- ...
       |                           |
  uplink A                      uplink B
  race LAN/public endpoints     race LAN/public endpoints
       |                           |
       +------ mutually authenticated QUIC ------> jax
```

## Configuration and installation

The macOS installer owns these runtime paths:

- daemon: `/usr/local/libexec/multipassd`
- config: `/Library/Application Support/Multipass/config.json`
- client private key: `/var/db/multipass/client.key`
- LaunchDaemon: `/Library/LaunchDaemons/eu.bearcove.multipassd.plist`
- IPC socket: `/var/run/multipassd.sock`

Inspect the non-mutating installation oracle without root, built binaries, or
connected Ethernet/Wi-Fi:

```bash
./install-mac.sh --plan
```

A real install creates the Ed25519 client identity and documentation-default
config only when absent. Reinstall preserves the existing key and the entire
operator-owned config, including endpoints, pinned server key, and uplinks. It
never prints private material. The LaunchDaemon receives only:

```text
/usr/local/libexec/multipassd --config /Library/Application Support/Multipass/config.json
```

The initial public-repository config deliberately contains documentation keys,
documentation endpoints, and zero uplinks. Replace those values through the
root-owned operator configuration before connecting. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the exact typed JSON shape.

Default uninstall removes runtime artifacts but preserves config and identity
for a later reinstall. `sudo ./uninstall-mac.sh --purge` is the explicit,
permanent deletion path.

## Dynamic IPC

The menubar app uses newline-delimited JSON on the configured Unix socket.
`connect` means persistent enabled intent, not immediate reachability. Status
reports `enabled`, `connected`, `active_uplink_id`, logical counters, and an
ordered `uplinks` array. Every entry includes stable ID, configured interface,
dynamic state, readiness, selected source/endpoint, RTT, counters, and a
secret-free last error. `enabled: true, connected: false` is the normal offline
waiting state when no authenticated uplink is ready.

## Status

**Experimental. The dual-stack tunnel and loss recovery work, but path failure
still causes a multi-second stall and aggregate throughput remains below either
raw link's capacity. Do not yet rely on the current build for latency-sensitive
seamless failover.**

Verified on the real `scooter` ↔ `jax` deployment before the current N-uplink
configuration/authentication cutover:

- Concurrent wired and Wi-Fi QUIC paths carried authenticated tunnel traffic.
- IPv4 tunnel reachability: 20/20 pings, 0% loss, 1.16 ms average.
- IPv6 tunnel reachability: 20/20 pings, 0% loss, 3.71 ms average.
- Native routed public IPv6 configuration is implemented but not yet
  production-verified.
- IPv4 and IPv6 HTTPS both completed through the tunnel.

Current throughput measurements (`iperf3`, four streams):

| Path | Throughput |
| --- | ---: |
| Raw wired | 2.35 Gbit/s |
| Raw Wi-Fi | 0.68 Gbit/s |
| Raw combined capacity | 3.03 Gbit/s |
| Tunnel upload | 0.260 Gbit/s |
| Tunnel download | 0.266 Gbit/s |

The scheduler preserves an exploration share for every eligible path. In
production measurements, Wi-Fi carried 5.1% of upload underlay traffic and 5.2%
of download underlay traffic. This fixes total path starvation but not the
broader throughput bottleneck.

Loss recovery preserved every probe during an eight-second wired QUIC
blackhole: concurrent IPv4 and IPv6 tunnel pings each delivered 250/250 packets.
The worst observed pause was approximately 2.37 seconds, so user-visible
failover is not yet seamless.

## Layout

- `crates/multipass` — client daemon, dynamic uplink lifecycle, utun, routing,
  and root-owned IPC.
- `crates/multipass-proto` — ALPN v4 wire format, identities, framing,
  acknowledgements, deduplication, and reliability logic.
- `crates/multipass-server` — authenticated server sessions and Linux TUN
  forwarding.
- `app/` — SwiftUI menubar app with ordered dynamic uplink status.
- `deploy/` — public, placeholder-only server deployment contract.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache 2.0](LICENSE-APACHE), at your option.
