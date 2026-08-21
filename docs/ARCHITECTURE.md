# multipass — architecture contract

Multipass is a macOS 27+ to Linux-router packet tunnel with a stable logical
session over a dynamic set of configured underlays. It carries raw IPv4 and
IPv6, aggregates every configured-enabled ready uplink, and remains enabled
while zero uplinks are currently usable.

## Core invariants

- The client configuration may contain zero, one, two, or more uplinks.
- A logical uplink has a stable ID and configured interface. Its addresses,
  route, selected gateway endpoint, connection, and generation are runtime
  state.
- One uplink owns at most one authenticated winning connection. Multiple
  reachable gateway endpoints are race candidates, not extra scheduler paths.
- One logical VPN epoch owns tunnel addresses, packet sequences, send windows,
  SACK/reorder state, counters, and application continuity. Replacing any one
  underlay connection does not replace that epoch.
- Both peers prove possession of explicitly provisioned persistent Ed25519
  identities. Scooter pins jax; jax authorizes scooter's public key and maps it
  to the stable `scooter` client ID.
- Private key material is root-only and is never logged or returned through IPC.
- Connect and Disconnect control persistent intent. `enabled=true` with zero
  ready uplinks is a valid waiting state.

## Configuration contract

Positional server/wired/Wi-Fi daemon arguments do not exist. `multipassd`
accepts only a typed root-owned JSON file:

```text
/usr/local/libexec/multipassd --config /Library/Application Support/Multipass/config.json
```

The exact `ClientConfigFile` JSON fields are:

```json
{
  "gateway": {
    "id": "jax",
    "server_public_key": "ed25519:ERERERERERERERERERERERERERERERERERERERERERE",
    "endpoints": [
      { "address": "192.0.2.1:51823", "display_name": "Home LAN" },
      { "address": "198.51.100.23:51823", "display_name": "Public IPv4" },
      { "address": "[2001:db8:1088:1c17::1]:51823", "display_name": "Public IPv6" }
    ]
  },
  "client": {
    "id": "scooter",
    "private_key_file": "/var/db/multipass/client.key"
  },
  "uplinks": [
    {
      "id": "desk-ethernet",
      "display_name": "Desk Ethernet",
      "interface": "en17",
      "enabled": true
    },
    {
      "id": "wifi",
      "display_name": "Wi-Fi",
      "interface": "en0",
      "enabled": true
    }
  ],
  "ipc_socket": "/var/run/multipassd.sock"
}
```

The public values are documentation examples. Real endpoints and keys belong in
private operator configuration. `uplinks: []` is valid for installation,
configuration staging, and persistent offline intent. Disabled uplinks remain
visible in status but do not resolve, route, or dial.

macOS runtime ownership:

| Path | Owner/mode | Policy |
| --- | --- | --- |
| `/Library/Application Support/Multipass/config.json` | `root:wheel 0600` | Created only when absent; operator contents preserved on reinstall. |
| `/var/db/multipass/client.key` | `root:wheel 0600` | Ed25519 private key created only when absent; preserved by default uninstall. |
| `/Library/LaunchDaemons/eu.bearcove.multipassd.plist` | `root:wheel 0644` | Atomically replaced from installer source. |
| `/usr/local/libexec/multipassd` | `root:wheel 0755` | Atomically replaced release binary. |
| `/var/run/multipassd.sock` | runtime | Path comes from validated config and is created by the daemon. |

`./install-mac.sh --plan` is the non-mutating oracle. It does not require root,
built artifacts, address discovery, Ethernet, Wi-Fi, or a default route. A real
install writes new config, plist, key, and app artifacts through temporary paths
before atomic rename. It never overwrites an existing identity or operator
config and never prints private data.

The exact `ServerConfigFile` JSON fields are:

```json
{
  "private_key_file": "/var/lib/multipass-server/server.key",
  "bind": "0.0.0.0:51823",
  "routed_ipv6_prefix": "2001:db8:99::/64",
  "authorized_clients": [
    {
      "id": "scooter",
      "public_key": "ed25519:IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"
    }
  ]
}
```

The server source-owned path is `/etc/multipass-server/config.json`; its
persistent identity is `/var/lib/multipass-server/server.key`. The service runs
`/usr/local/bin/multipass-server --config /etc/multipass-server/config.json`.
The real routed prefix and authorized scooter key remain in private deployment
source.

## Mutual pinned authentication and ALPN

QUIC negotiates ALPN `multipass/4`. Version 4 binds the authenticated Hello to:

- stable client ID;
- logical client epoch;
- stable uplink ID;
- compact session-local path ID;
- connection generation.

Scooter validates the exact configured jax public key, independent of LAN or
public address. Jax validates the client key against `authorized_clients` and
uses the associated client ID. WebPKI hostname trust, trust on first use,
accept-any-certificate verification, and anonymous clients are not part of the
contract.

A newer authenticated generation replaces only the same logical uplink. A
mismatched identity never wins an endpoint race and is not downgraded to an
unauthenticated connection.

## Endpoint racing and roaming

Each enabled uplink independently:

1. observes usable addresses on its configured interface;
2. pairs IPv4 sources with IPv4 endpoints and IPv6 sources with IPv6 endpoints;
3. resolves a native service route without consulting the utun default;
4. acquires an endpoint-specific scoped host-route lease;
5. races compatible candidates concurrently;
6. installs the first candidate that completes pinned mutual authentication;
7. closes losers and releases their route leases;
8. publishes the selected source and endpoint for diagnostics.

At home the LAN endpoint should normally authenticate first. Away from home,
public IPv4 or IPv6 can win. No address auto-detection, current-default-gateway
inference, SSID allowlist, or special home mode is required.

Native network changes increment the affected uplink generation. Stale route or
dial completions cannot replace newer state. Losing an address, route, or QUIC
connection moves only that uplink to waiting/backoff; other ready uplinks and the
logical epoch survive.

## Send policy and reliability

The send path stripes each raw IP packet onto one ready path chosen by estimated
delivery cost (RTT plus queue pressure). Every packet remains in a bounded
`SendWindow` until the peer's selective ACK confirms receipt.

The receiver tracks arrivals in a `SackScoreboard` and broadcasts SACKs across
ready paths. On a gap, path death, or recovery, the sender can retransmit the
same sequence on a survivor. `Dedup` prevents a retransmission from reaching the
tunnel twice. Both directions use the same aggregation and recovery contract.

QUIC datagrams carry raw IP packets. Streams would impose ordered byte-stream
semantics and would not transparently carry UDP or ICMP. The inner protocol
remains ordinary IPv4/IPv6; inner TCP retains its own end-to-end behavior.

## Components

### `multipass-proto`

Shared wire format and allocation-bounded reliability logic:

- ALPN `multipass/4`;
- `Data`, authenticated `Hello`, `Assign`, `Ping`, `Pong`, and `Sack` frames;
- stable `ClientId` and `UplinkId`, compact `PathId`;
- `Dedup`, `SackScoreboard`, `SendWindow`, and scheduler primitives;
- IPv4/IPv6 tunnel assignment, MTU 1280, and server build identity.

### `multipassd`

Root macOS LaunchDaemon:

- atomically loads and validates config plus the secure client key before
  binding IPC;
- owns the utun device, routes, endpoint-specific underlay route leases, and
  logical tunnel state;
- runs one independent lifecycle controller per configured uplink;
- races compatible gateway endpoints and installs at most one authenticated
  winner per uplink;
- stripes tunnel packets over the dynamic ready set and preserves reliability
  state across connection replacement;
- exposes newline-delimited JSON on the config-owned Unix socket.

### `multipass-server`

Linux router service:

- loads its root-owned config and persistent server identity;
- accepts only authorized mutually authenticated clients;
- groups any number of authenticated uplinks for one client epoch into one
  logical session, without wired/Wi-Fi slots or acceptance-order identity;
- owns Linux TUN forwarding, symmetric scheduling/recovery, IPv4 masquerading,
  and deployment-selected IPv6 forwarding.

### Multipass app

The SwiftUI menubar app is unprivileged. It sends `status`, `connect`,
`disconnect`, and benchmark-topology commands over the Unix socket. It renders
the ordered dynamic uplink array and distinguishes enabled intent from current
connectivity.

## Dynamic IPC contract

Status contains:

- `enabled`: persistent VPN intent;
- `connected`: at least one mutually authenticated ready uplink and an active
  logical tunnel;
- nullable `active_uplink_id`;
- logical `tx` and `rx` counters;
- ordered `uplinks` entries with `id`, `display_name`, `interface`,
  `configured_enabled`, `state`, `ready`, nullable `source_address`, nullable
  `gateway_endpoint`, nullable `rtt_ms`, per-uplink counters, and nullable
  secret-free `last_error`.

With zero ready uplinks, the daemon remains enabled, status remains available,
configured uplinks keep their current states, and reconnection resumes when
native addresses/routes appear. The user does not need to press Connect again.
An explicit Disconnect stops acquisition/dialing, closes connections, tears
down tunnel routing, and ends the logical session.

## Tunnel network

Server UDP port is 51823. The current well-known IPv4 tunnel subnet is
`10.10.99.0/24` (server `.1`, client `.2`). The current ULA layout is
`fd00:99::/64` (server `::1`, client `::2`) when NAT66 is selected. A deployment
may instead provide a native routed `/64` in the server config. MTU is 1280.

## Non-goals

- automatic discovery of every eligible interface;
- treating alternate endpoints on one uplink as independent bandwidth paths;
- trust on first use or public-CA gateway identity;
- multi-client tunnel-address allocation;
- Windows/Linux production clients;
- DNS configuration through the tunnel.
