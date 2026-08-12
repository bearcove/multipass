# N-Uplink Roaming VPN Design

**Date:** 2026-08-11

**Status:** Approved design

## Purpose

Replace Multipass's fixed wired/Wi-Fi transport with an N-uplink VPN architecture. The same logical tunnel must operate with zero, one, two, or more underlays, preserve sessions while underlays appear or disappear, and reach the authenticated jax gateway through LAN IPv4, public IPv4, or public IPv6.

The immediate policy is deliberately narrow: configured uplinks may be enabled or disabled, and all enabled, authenticated, ready uplinks participate in the existing aggregation scheduler. This is enough to isolate wired-only, Wi-Fi-only, two-wired, and mixed-path performance. The architecture must leave a clean policy boundary for later ordered failover, replication, aggregation groups, metered-link avoidance, and traffic-specific rules.

This design also promotes Multipass from a desk-only experiment into a real roaming VPN. At home it may aggregate Ethernet and Wi-Fi. Away from home, Wi-Fi, tethering, or cellular underlays reach the same logical gateway over public endpoints without changing the tunnel identity or resetting application sessions.

## Goals

- Support any configured number of uplinks, including zero while waiting for connectivity.
- Give each logical uplink a stable configuration identity independent of interface address, gateway endpoint, or connection generation.
- Resolve an uplink's current source addresses from its configured interface.
- Race all compatible jax endpoints independently for each uplink and retain one authenticated connection per uplink.
- Preserve one logical tunnel session, tunnel addresses, sequence space, reliability windows, and application sessions while connections are replaced.
- Authenticate both jax and clients using explicitly pinned persistent identities.
- Protect underlay routes for uplinks that appear after the full-tunnel default has already been installed.
- Replace fixed wired/Wi-Fi status, counters, UI rows, server slots, and scheduler arrays with dynamic collections.
- Provide a policy seam that can support arbitrary failover and aggregation rules without rewriting transport lifecycle code.
- Permit controlled single-uplink and multi-uplink production benchmarks without attributing poor efficiency to an underlay before isolation.

## Non-goals for this cutover

- A user-facing arbitrary rule editor.
- A general rule language or graph evaluator.
- Multi-client tunnel address allocation beyond the existing one-client deployment.
- Automatic discovery of every eligible interface. The initial configuration lists logical uplinks explicitly.
- Treating multiple jax endpoints reachable through one interface as independent aggregation paths.
- Trust on first use, bearer-token authentication, or public-CA certificate issuance.
- Platform-independent underlay route implementation. The abstraction is portable; this cutover implements macOS.

## Core concepts

### Logical gateway

Jax is one logical VPN gateway with a stable cryptographic identity and several reachable socket endpoints:

```rust
struct GatewayConfig {
    id: GatewayId,
    server_public_key: PublicKey,
    endpoints: Vec<GatewayEndpoint>,
}

struct GatewayEndpoint {
    address: SocketAddr,
    display_name: Option<String>,
}
```

Endpoints may include:

- jax's LAN IPv4 address;
- jax's exposed public IPv4 address;
- an address from jax's routed public IPv6 prefix.

An endpoint is a dialing candidate, not a scheduler path. Reaching the same physical uplink through LAN IPv4 and public IPv6 does not create two units of independent capacity.

### Logical uplink

A configured uplink identifies a policy-addressable underlay source:

```rust
struct UplinkConfig {
    id: UplinkId,
    display_name: String,
    interface: String,
    enabled: bool,
}
```

`UplinkId` is an explicit stable configuration string. It is not an interface name or IP address. Examples include `desk-ethernet`, `wifi`, `usb-ethernet`, and `iphone-tether`.

The interface name and resolved addresses are mutable attributes. DHCP changes, IPv6 prefix changes, and replacement connection generations do not change the uplink identity.

Configuration order is stable and controls presentation order only. It never implies priority unless a later policy explicitly assigns priority.

### Session-local path ID

Hot protocol and scheduler code uses a compact opaque `PathId`, allocated by the client for the active logical session. Human-facing configuration and status use `UplinkId`.

The mapping is explicit and retained for the epoch:

```rust
struct RegisteredUplink {
    id: UplinkId,
    path_id: PathId,
    config: UplinkConfig,
    runtime: UplinkRuntime,
}
```

Removing `PathKind::{Wired, Wifi}` is a clean cutover. No aliases or compatibility fields remain.

### Connection candidate

A candidate is one attempt to connect a source address on one uplink to one compatible gateway endpoint:

```rust
struct ConnectionCandidate {
    uplink_id: UplinkId,
    uplink_generation: u64,
    source_address: IpAddr,
    endpoint: GatewayEndpoint,
    underlay_route: UnderlayRouteLease,
}
```

A candidate exists only after Multipass has independently resolved and protected its native underlay route.

## Configuration

A root-owned typed JSON configuration replaces positional wired/Wi-Fi command-line arguments. The repository already uses `facet` and `facet-json`; configuration must use those typed models rather than hand-written JSON parsing.

Illustrative shape:

```json
{
  "gateway": {
    "id": "jax",
    "server_public_key": "ed25519:11qYAYLefR7xvK3vpxk4L4dC7A0KzY8Vw3uO5nQ2sE",
    "endpoints": [
      { "address": "10.10.10.1:51823", "display_name": "Home LAN" },
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

The LaunchDaemon invokes only:

```text
/usr/local/libexec/multipassd --config /Library/Application Support/Multipass/config.json
```

Requirements:

- The configuration file is owned by root and not writable by unprivileged users.
- The private-key file is readable only by root.
- The private key and raw key material are never returned over IPC or logged.
- Duplicate gateway endpoints, duplicate `UplinkId` values, empty uplink sets, invalid interfaces, and malformed keys produce typed validation errors.
- An empty uplink set is valid for persistent offline intent and configuration staging.
- Disabled uplinks remain visible in status but do not resolve addresses, install routes, or dial.

The server uses a root-owned configuration containing its private identity and an allowlist mapping authorized client public keys to stable client IDs. Public endpoint addresses do not affect identity.

## Mutual pinned authentication

The current client certificate verifier accepts any server certificate, and the server requests no client identity. Both behaviors are removed.

### Identity model

- Jax owns a persistent Ed25519 private key.
- Scooter owns a persistent Ed25519 private key.
- Scooter pins jax's public key.
- Jax authorizes scooter's public key and maps it to the `scooter` client identity.
- QUIC TLS proves possession of both private keys.
- The same jax identity is valid on LAN IPv4, public IPv4, and public IPv6.
- Protocol metadata is accepted only after TLS authentication and is bound to the authenticated peer identity.

Self-signed TLS certificates may be used as containers for the pinned keys, but validation is exact public-key identity validation, not WebPKI hostname validation and not certificate acceptance by shape. A candidate with a mismatched key fails terminally for that endpoint generation. It is never downgraded to an unauthenticated connection.

Key rotation is explicit configuration. Overlap may be represented as an allowed set during a controlled rotation, but trust on first use is prohibited.

### Authenticated hello

After TLS authentication, the client sends session metadata:

```rust
struct UplinkHello {
    client_epoch: u64,
    uplink_id: UplinkId,
    path_id: PathId,
    connection_generation: u64,
}
```

The server verifies that:

- the transport peer is an authorized client;
- the claimed client ID matches the authenticated key mapping;
- the epoch belongs to that authenticated client;
- `UplinkId` and `PathId` are not conflicting with another active mapping;
- the generation is newer than the currently installed generation for that uplink.

A newer authenticated generation for one uplink atomically supersedes the older connection. Other uplinks in the epoch remain live.

## Uplink registry

The client transport owns an ordered dynamic registry keyed by `UplinkId`; lookup by `PathId` is also available for the packet path:

```rust
struct UplinkRegistry {
    ordered: Vec<RegisteredUplink>,
    by_id: HashMap<UplinkId, usize>,
    by_path_id: HashMap<PathId, usize>,
}
```

The exact storage may differ to avoid duplicate ownership, but these invariants hold:

- IDs are unique and stable.
- Iteration order matches configuration order.
- Hot scheduler lookup by `PathId` does not scan strings.
- Adding, replacing, or removing a connection does not rebuild unrelated uplink state.
- Status snapshots are immutable owned values and do not hold transport locks during IPC serialization.

Each runtime uplink tracks:

```rust
struct UplinkRuntime {
    generation: u64,
    state: UplinkState,
    resolved_sources: Vec<IpAddr>,
    connection: Option<AuthenticatedConnection>,
    selected_source: Option<IpAddr>,
    selected_endpoint: Option<SocketAddr>,
    last_error: Option<UplinkError>,
    counters: UplinkCounters,
    probe: ProbeState,
}
```

`UplinkState` has observable states including disabled, waiting for address, resolving route, racing endpoints, authenticating, ready, and backoff. Errors remain associated with the relevant uplink and generation.

## Address and network-state resolution

Each enabled uplink resolves usable addresses currently assigned to its configured interface.

Eligibility rules:

- IPv4 sources pair only with IPv4 endpoints.
- IPv6 sources pair only with IPv6 endpoints.
- Loopback, link-local, multicast, unspecified, and tunnel-owned addresses are excluded.
- IPv6 scope must be valid for the destination.
- Address or service-route changes increment the uplink generation.
- A result from an older generation cannot install a route or connection.

The daemon subscribes to native network-state notifications. Polling may remain as a bounded safety net, but it is not the sole roaming mechanism.

## Underlay route authority

### Problem

After Multipass installs the full-tunnel default through utun, ordinary route lookup points at the tunnel. That lookup cannot discover the native path for an uplink that appears later, which is the central roaming case. Binding a socket to a source address is not sufficient protection against recursion.

### Resolver contract

Underlay routing is owned by a dedicated abstraction:

```rust
trait UnderlayRouteResolver {
    fn resolve(
        &self,
        uplink: &UplinkConfig,
        source: IpAddr,
        endpoint: IpAddr,
    ) -> Result<UnderlayRoute, RouteError>;
}
```

The macOS implementation derives route state from native interface/service configuration, such as SystemConfiguration or equivalent Network.framework state. It does not use the post-tunnel default route as fallback.

The resolver supplies:

```rust
struct UnderlayRoute {
    endpoint: IpAddr,
    interface: String,
    source: IpAddr,
    next_hop: Option<IpAddr>,
    family: AddressFamily,
    network_generation: u64,
}
```

It must determine:

- the interface and service owning the source address;
- the service's native IPv4 router when required;
- the service's native IPv6 router, prefix, and scope when required;
- whether the endpoint is reachable through that service independently of utun;
- the correct source address for the endpoint family.

Candidates without an independently resolved native route are ineligible.

### Route leases

Before a candidate dials, Multipass installs an endpoint-specific scoped host route using the resolved native route. Installation returns a lease:

```rust
struct RouteKey {
    endpoint: IpAddr,
    interface: String,
    source: IpAddr,
    next_hop: Option<IpAddr>,
}

struct UnderlayRouteLease {
    key: RouteKey,
    generation: u64,
}
```

Route ownership is reference-counted because concurrent candidates may temporarily share a route. A route is removed only after its final owner releases it.

Lifecycle:

1. Observe current native service and address state.
2. Resolve a candidate's underlay route without consulting the tunnel default.
3. Install or acquire the scoped endpoint route.
4. Bind QUIC to the resolved source address.
5. Dial and mutually authenticate.
6. Retain the lease for the winning connection.
7. Release losing candidates' leases.
8. Invalidate affected generations on network change.
9. Release a winning connection's lease only after the connection is superseded or closed.

A stale route resolution or dial completion cannot replace state from a newer network generation.

This contract explicitly covers a new Wi-Fi, USB Ethernet, tethering, or cellular uplink appearing while utun already owns the default route.

## Endpoint racing

Each enabled uplink independently races every compatible source-address × gateway-endpoint candidate.

For one uplink generation:

1. Resolve current usable source addresses.
2. Form compatible address-family pairs with configured gateway endpoints.
3. Acquire an underlay route lease for every eligible pair.
4. Dial candidates concurrently.
5. Complete QUIC TLS and mutual pinned authentication.
6. Atomically install the first authenticated connection.
7. Cancel or close all losing candidates and release their route leases.
8. Publish the selected source and endpoint for diagnostics.

The race winner is route discovery for one physical/logical uplink. Losing or alternate endpoints do not remain as scheduler paths.

At home, the LAN endpoint should normally win because authentication completes first. Away from home, public IPv4 or IPv6 wins. No location detector, SSID allowlist, or home-network special case is required.

Failure behavior:

- Authentication mismatch is reported distinctly from network failure.
- One candidate's failure does not cancel viable siblings.
- If all candidates fail, the uplink enters bounded backoff while VPN intent remains enabled.
- Network-state change cancels backoff and starts a new generation immediately.

## Persistent VPN intent and connection lifecycle

Connect and Disconnect control intent, not momentary reachability.

```text
disabled
   | Connect
enabled / waiting for address
   | native address and route appear
racing endpoints
   | first authenticated winner
ready
   | address, route, liveness, or authentication loss
waiting or bounded backoff
```

With zero ready uplinks:

- the daemon remains enabled;
- status reports enabled but disconnected;
- configured uplinks remain visible with their states and errors;
- reconnection continues as interfaces and routes appear;
- the user does not need to press Connect again.

An explicit Disconnect stops route acquisition and dialing, closes all connections, tears down tunnel routing, and ends the logical session.

## Logical tunnel continuity

The client epoch belongs to the logical VPN session, not to a connection or uplink. Replacing an endpoint, source address, interface address, or complete QUIC connection must not reset:

- assigned tunnel IPv4 or IPv6 addresses;
- outbound sequence numbers;
- send windows;
- receive SACK and reorder state;
- tunnel byte counters for the epoch;
- application TCP, UDP, or ICMP sessions.

Only explicit Disconnect or a protocol-defined unrecoverable session replacement starts a new epoch.

The server groups every authenticated uplink connection for one client epoch into one session. It does not assign wired/Wi-Fi slots or infer identity from acceptance order. Any number of uplinks may be active.

## Send-policy boundary

Connection lifecycle and traffic policy are separate.

Connection management publishes immutable snapshots:

```rust
struct UplinkSnapshot {
    id: UplinkId,
    path_id: PathId,
    configured_enabled: bool,
    state: UplinkState,
    ready: bool,
    rtt: Option<Duration>,
    congestion_window: u64,
    send_capacity: usize,
    metered: Option<bool>,
}
```

The policy receives snapshots and packet metadata and returns a decision:

```rust
trait SendPolicy {
    fn decide(
        &mut self,
        uplinks: &[UplinkSnapshot],
        packet: &PacketMeta,
    ) -> SendDecision;
}

enum SendDecision {
    One(PathId),
    Replicate(SmallVec<PathId>),
    Hold,
}
```

The immediate `EnabledAggregationPolicy`:

- includes every configured-enabled, authenticated, ready uplink;
- uses the existing RTT/congestion-window/send-capacity scheduler to choose one path;
- selects the only ready path when N = 1;
- returns `Hold` when N = 0;
- never sends through a disabled or unready uplink.

Future policies may implement:

- ordered primary/fallback groups;
- active-active aggregation groups;
- replication for selected traffic;
- metered or expensive uplink avoidance;
- latency-sensitive versus bulk traffic classes;
- location, power, or user-rule predicates.

Those policies must not own dialing, authentication, route leases, packet sequence state, or connection replacement.

## Dynamic scheduler

The scheduler replaces `[PathState; 2]` and `PathKind` indexing with dynamic state keyed by compact `PathId`.

Requirements:

- N = 0 returns no selection.
- N = 1 always selects that eligible path.
- N > 1 preserves deterministic weighted behavior for a fixed sequence of observations.
- Eligibility, RTT, congestion window, and send capacity are updated per `PathId`.
- Removing a path removes its accumulated scheduler state.
- Adding a path starts with explicit neutral/default state and cannot corrupt existing weights.
- The hot path does not allocate per packet.

The current exploration-floor behavior may remain for the first cutover so the N-uplink refactor does not silently change scheduling semantics. Performance attribution and scheduler correction follow isolated N = 1 and N > 1 measurements.

## Reliability and packet flow

Send-window, SACK, retransmission, deduplication, and reorder state remain session-level. They are not duplicated per uplink.

Inbound `Data` identifies the delivering `PathId`; status maps it back to `UplinkId`. Outbound retained packets may be retransmitted through any policy-eligible ready path.

A connection death:

- marks only that uplink generation unavailable;
- removes it from policy candidates;
- triggers retained-packet recovery on remaining eligible paths;
- starts route/address resolution and endpoint racing for that uplink;
- does not reset sequence state.

## Server session registry

The server session stores a dynamic connection registry for the authenticated client epoch:

```rust
struct SessionConnection {
    authenticated_client: ClientId,
    uplink_id: UplinkId,
    path_id: PathId,
    generation: u64,
    connection: Connection,
    ready: bool,
    counters: PathCounters,
}
```

Requirements:

- Any number of distinct uplinks may join the epoch.
- A newer generation atomically supersedes the older connection for the same uplink.
- A stale or duplicate generation is rejected.
- `PathId` conflicts are rejected rather than silently reassigned.
- Scheduler and broadcast loops iterate dynamic ready connections.
- SACK and control broadcasts reach every ready connection without fixed slots.
- One connection's failure cannot retire unrelated connections.

## IPC contract

The fixed wired/Wi-Fi status fields are replaced with an ordered array:

```json
{
  "type": "status",
  "enabled": true,
  "connected": true,
  "active_uplink_id": "wifi",
  "tx": 123456,
  "rx": 789012,
  "uplinks": [
    {
      "id": "desk-ethernet",
      "display_name": "Desk Ethernet",
      "interface": "en17",
      "configured_enabled": true,
      "state": "waiting_for_address",
      "ready": false,
      "source_address": null,
      "gateway_endpoint": null,
      "rtt_ms": null,
      "tx": 0,
      "rx": 0,
      "last_error": null
    },
    {
      "id": "wifi",
      "display_name": "Wi-Fi",
      "interface": "en0",
      "configured_enabled": true,
      "state": "ready",
      "ready": true,
      "source_address": "192.0.2.10",
      "gateway_endpoint": "[2001:db8::10]:51823",
      "rtt_ms": 18.4,
      "tx": 123456,
      "rx": 789012,
      "last_error": null
    }
  ]
}
```

Semantics:

- `enabled` is persistent VPN intent.
- `connected` means at least one mutually authenticated uplink is ready and the logical tunnel is active.
- `active_uplink_id` is the most recent first-delivery uplink used for the existing failover indication; it is null without a ready delivery path.
- `uplinks` preserves configuration order.
- Per-uplink counters include physical-path payload, including retransmissions and pre-dedup receive bytes, matching the existing diagnostic meaning.
- Counter monotonicity holds for the logical epoch. Replacing a connection generation does not reset its logical uplink counters.
- Authentication and routing failures are distinguishable in `state` and `last_error` without exposing secrets.

The benchmark-topology reply continues to use an array and obtains source addresses dynamically. A configured uplink with no current source address remains present but is unavailable for a physical benchmark.

## SwiftUI app

The app removes `ActivePath`, `wiredLive`, `wifiLive`, fixed per-path rates, and hard-coded rows. It decodes arbitrary ordered uplink snapshots and derives per-ID rates from cumulative counters.

The menu renders one row per configured uplink:

- configured display name and interface;
- enabled/disabled state;
- runtime state and ready indication;
- selected source and endpoint in diagnostics;
- RTT and directional rates;
- active/failover indication keyed by `UplinkId`.

Initial interaction may expose an enable/disable control per uplink if the daemon IPC supports configuration mutation safely. If configuration mutation is not included in the first implementation slice, selection-only experiments use the root-owned config and app rendering remains read-only. A general policy editor remains future scope.

The app distinguishes:

- VPN disabled;
- VPN enabled and waiting for connectivity;
- VPN connected through one or more uplinks;
- daemon unavailable.

## Installer and deployment

The macOS installer:

- installs the daemon and app as before;
- installs or preserves the root-owned typed config;
- installs or preserves the client identity key;
- never regenerates an existing identity during an ordinary reinstall;
- passes only `--config` to launchd;
- reports configured uplinks and gateway endpoints without printing private material;
- does not require both Ethernet and Wi-Fi to be connected at install time.

Jax deployment:

- installs or preserves its server identity;
- configures the authorized client-key allowlist;
- listens on the existing QUIC port on LAN/public IPv4/public IPv6 as routing and firewall policy permit;
- keeps the real public addresses and routed prefix in private deployment configuration, not this public repository.

## Error handling and observability

Every error is scoped to its owner and generation:

- configuration errors prevent daemon startup;
- one uplink's missing interface or address does not disable other uplinks;
- one endpoint's network failure does not cancel sibling candidates;
- authentication mismatch is distinct from timeout or refusal;
- route-resolution failure prevents dialing that candidate;
- stale asynchronous results are rejected by generation;
- logical-session failure is distinguished from path failure.

Tracing fields include client ID, uplink ID, path ID, generation, source address, endpoint, route generation, and state transition. Private keys and raw authentication proofs are never logged.

Status exposes a bounded last error per uplink for operator diagnosis. Repeated retry logs are rate-limited or transition-based rather than emitted for every tick.

## Verification contract

### Automated behavior

Production-facing tests must prove:

1. Dynamic scheduler behavior for N = 0, 1, 2, and 3.
2. One ready uplink receives every selected packet in N = 1 mode.
3. Disabled and unready uplinks never receive ordinary data.
4. Dynamic insertion, replacement, and removal preserve unrelated uplink state.
5. Connection replacement preserves client epoch and packet sequence state.
6. Endpoint racing retains only the first mutually authenticated winner.
7. A stale candidate generation cannot replace a newer connection.
8. Unknown server keys are rejected by the client.
9. Unknown client keys are rejected by jax.
10. The authenticated client identity is bound to hello metadata.
11. IPC serializes arbitrary ordered uplink arrays and no fixed wired/Wi-Fi fields.
12. Swift models and rate derivation handle one, two, and three uplinks by stable ID.
13. Server sessions accept N connections and replace only the matching uplink generation.
14. The underlay resolver never falls back to the utun default.
15. An uplink appearing after full-tunnel activation resolves a native service route, installs an owned endpoint route, and authenticates without recursion.
16. Route leases are reference-counted and stale generations cannot remove current routes.
17. Connect with zero usable uplinks remains enabled and later connects without another Connect command.

Tests defend these observable contracts rather than source structure. Real QUIC handshakes are used for authentication and endpoint-race tests.

### Production experiments

Run every available topology independently:

- Wi-Fi only;
- wired only after a cable is attached;
- each wired adapter independently;
- two wired adapters together;
- mixed wired and Wi-Fi;
- non-home WAN IPv4;
- non-home WAN IPv6;
- live transition between LAN and public gateway endpoints without logical tunnel restart.

For each topology record:

- configured and ready uplink IDs;
- winning gateway endpoint per uplink;
- raw physical upload/download throughput;
- tunnel IPv4 and IPv6 upload/download throughput;
- tunnel efficiency against the active physical capacity;
- inner retransmits;
- per-uplink underlay bytes;
- session epoch before and after transitions;
- continuity gaps for concurrent TCP, UDP, ICMPv4, and ICMPv6 traffic.

Both wired links are currently disconnected, so the refactor and automated verification proceed without them. Live wired-only and two-wired measurements remain explicit acceptance experiments when the interfaces are physically available.

No performance cause is attributed to Wi-Fi, Ethernet, scheduling, QUIC, encryption, routing, or another subsystem without an experiment that isolates that variable.

## Migration and clean cutover

The implementation migrates all callers and removes:

- `PathKind::{Wired, Wifi}` and `PathKind::ALL`;
- fixed two-element scheduler state;
- `Transport { wired, wifi }`;
- positional daemon source-address arguments for exactly one wired and one Wi-Fi interface;
- fixed server connection slots;
- fixed daemon `PathSnapshot` fields;
- wired/Wi-Fi IPC status fields;
- Swift `ActivePath` enum and hard-coded path rows;
- installer assumptions that both paths are present;
- documentation claiming exactly two connections or LAN-only routing;
- the unauthenticated TLS verifier and no-client-auth server configuration.

No compatibility aliases, deprecated fields, or fallback unauthenticated modes remain.

## Design invariants

1. Gateway identity is independent of gateway endpoint.
2. Uplink identity is independent of interface address and connection generation.
3. One logical uplink contributes at most one ready scheduler path.
4. Endpoint racing never creates artificial aggregation capacity.
5. Traffic policy never owns connection lifecycle or underlay routes.
6. Logical session state survives individual connection replacement.
7. Every candidate has an independently resolved native underlay route before dialing.
8. Ordinary post-tunnel route lookup is never used as underlay-route authority.
9. Only mutually pinned authenticated peers join a logical session.
10. Zero ready uplinks is a recoverable enabled state, not an implicit Disconnect.
11. Hot packet scheduling uses compact IDs and performs no avoidable per-packet allocation.
12. Status and UI treat uplinks as an ordered dynamic collection.
