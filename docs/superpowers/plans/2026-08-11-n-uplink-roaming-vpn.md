# N-Uplink Roaming VPN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Multipass's fixed wired/Wi-Fi tunnel with a dynamically configured, mutually authenticated N-uplink roaming VPN that preserves one logical session while underlays and jax endpoints change.

**Architecture:** Introduce stable `UplinkId` and compact session-local `PathId` identities in the shared protocol, then migrate scheduler, client transport, server sessions, daemon state, IPC, and SwiftUI to ordered dynamic collections. Keep gateway endpoint racing, native underlay route acquisition, and send policy as separate components. The initial policy aggregates every configured-enabled ready uplink; later rule systems can replace that policy without changing connection lifecycle or reliability state.

**Tech Stack:** Rust 2024, noq 1.1.1 QUIC, rustls 0.23, facet/facet-json typed configuration and IPC, Tokio, macOS SystemConfiguration/route sockets, Swift 6.4, SwiftUI Observation, Swift Testing.

## Global Constraints

- Clean cutover: remove `PathKind`, fixed wired/Wi-Fi fields, positional two-source arguments, and unauthenticated TLS; no compatibility aliases.
- Gateway identity is pinned independently from LAN/public IPv4/public IPv6 endpoints.
- Client identity is mutually authenticated and authorized by jax.
- One logical uplink retains at most one authenticated winning connection; endpoint candidates are not extra scheduler capacity.
- The logical epoch, tunnel addresses, packet sequences, send window, SACK/reorder state, and application sessions survive connection replacement.
- Connect with zero usable uplinks remains enabled and waits for network availability.
- Late-arriving uplinks resolve native per-service routes without consulting the utun default.
- Hot packet scheduling uses compact IDs and performs no avoidable per-packet allocation.
- Use `cargo nextest`, never `cargo test`.
- Follow TDD: add each observable-contract test, run it and confirm the expected failure, implement minimally, then rerun.
- Both wired interfaces are currently disconnected. Complete automated and Wi-Fi-only verification now; run wired-only and two-wired production benchmarks when those interfaces become physically available.

---

### Task 1: Shared identities, handshake, and dynamic scheduler

**Files:**
- Modify: `crates/multipass-proto/src/lib.rs`
- Modify: `crates/multipass-proto/src/scheduler.rs`
- Test: unit tests in both files

**Interfaces:**
- Produces: `PathId`, `UplinkId`, authenticated hello metadata encoding, and a dynamic `Scheduler` keyed by `PathId`.
- Consumes: existing `Frame`, `Scheduler`, and framing helpers.

- [ ] **Step 1: Add failing identity and frame round-trip tests**

Add tests proving:

```rust
let frame = Frame::Hello {
    client_epoch: 42,
    uplink_id: UplinkId::new("wifi").unwrap(),
    path_id: PathId::new(7),
    connection_generation: 3,
};
assert_eq!(decode(&encode(&frame)), Some(frame));
```

Also test rejection of empty, oversized, and malformed uplink IDs at the typed construction/decoding boundary.

- [ ] **Step 2: Run the focused tests and confirm RED**

```bash
cargo nextest list -E 'package(multipass-proto) & test(hello_)'
cargo nextest run -E 'package(multipass-proto) & test(hello_)'
```

Expected: compilation or assertion failure because dynamic identities and hello fields do not exist.

- [ ] **Step 3: Implement identities and hello encoding**

Implement:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PathId(u16);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UplinkId(Box<str>);
```

Use bounded length-prefixed UTF-8 on the wire. Keep `PathId` compact and `UplinkId` out of the per-packet `Data` frame.

- [ ] **Step 4: Add failing dynamic scheduler tests**

Prove N = 0, 1, 2, and 3; insertion/removal; disabled eligibility; deterministic weighted picks; and no stale state after removal.

- [ ] **Step 5: Run scheduler tests and confirm RED**

```bash
cargo nextest list -E 'package(multipass-proto) & test(scheduler)'
cargo nextest run -E 'package(multipass-proto) & test(scheduler)'
```

- [ ] **Step 6: Replace fixed scheduler storage**

Replace `[PathState; 2]` and `PathKind` indexing with registration-time dynamic storage keyed by `PathId`. Use a stable vector plus ID-to-index map so `pick()` iterates preallocated states without allocating. Provide explicit `insert`, `remove`, `set_eligible`, `note_rtt`, `note_path_stats`, and `note_queue_space` operations.

- [ ] **Step 7: Run protocol tests**

```bash
cargo nextest run -p multipass-proto
```

- [ ] **Step 8: Commit**

```bash
git add crates/multipass-proto
git commit -m "refactor: add dynamic uplink identities"
```

### Task 2: Typed client/server configuration and pinned identities

**Files:**
- Create: `crates/multipass/src/config.rs`
- Create: `crates/multipass/src/identity.rs`
- Create: `crates/multipass-server/src/config.rs`
- Create: `crates/multipass-server/src/identity.rs`
- Modify: `crates/multipass/src/lib.rs`
- Modify: `crates/multipass/Cargo.toml`
- Modify: `crates/multipass-server/Cargo.toml`
- Modify: workspace `Cargo.toml` only for source-verified dependencies required by Ed25519 key encoding/signing
- Test: unit tests in new modules plus real local QUIC handshake tests

**Interfaces:**
- Produces: validated `ClientConfigFile`, `ServerConfigFile`, persistent key loading, exact server-key pinning, and client-key authorization.
- Consumes: `GatewayEndpoint`, `UplinkId`, rustls 0.23 verifier/resolver APIs.

- [ ] **Step 1: Inspect current rustls/noq source APIs**

Read the installed rustls 0.23 and noq 1.1.1 source for custom server verification, client certificate resolution, peer certificate extraction, and QUIC config conversion. Do not infer signatures.

- [ ] **Step 2: Add failing configuration tests**

Use real facet-json input and assert:

- zero uplinks is valid;
- duplicate uplink IDs fail;
- duplicate endpoints fail;
- empty/invalid IDs fail;
- malformed keys fail;
- disabled uplinks remain represented.

- [ ] **Step 3: Run config tests and confirm RED**

```bash
cargo nextest list -E 'package(multipass) & test(config) | package(multipass-server) & test(config)'
cargo nextest run -E 'package(multipass) & test(config) | package(multipass-server) & test(config)'
```

- [ ] **Step 4: Implement typed facet-json configuration**

Provide exact models for gateway identity/endpoints, client identity/key file, ordered uplinks, IPC socket, server key, bind address, routed IPv6 prefix, and authorized clients. Parsing returns typed path-aware errors and validation is separate from deserialization.

- [ ] **Step 5: Add failing mutual-auth handshake tests**

Create temporary persistent test identities and real local QUIC endpoints. Prove:

- authorized client + pinned server succeeds;
- wrong server key fails;
- unauthorized client key fails;
- claimed client ID cannot disagree with the authenticated key mapping.

- [ ] **Step 6: Run handshake tests and confirm RED**

Use a focused nextest filter verified by `list` first.

- [ ] **Step 7: Implement exact pinned mutual authentication**

Replace `SkipVerify` and `with_no_client_auth`. Load existing keys without regeneration. Bind protocol client identity to the TLS-authenticated peer. Ensure private material is neither formatted nor logged.

- [ ] **Step 8: Run client/server auth tests**

```bash
cargo nextest run -E 'package(multipass) | package(multipass-server)'
```

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock crates/multipass crates/multipass-server
git commit -m "feat: add pinned VPN identities and config"
```

### Task 3: Dynamic client transport registry and policy seam

**Files:**
- Create: `crates/multipass/src/uplink.rs`
- Create: `crates/multipass/src/policy.rs`
- Modify: `crates/multipass/src/lib.rs`
- Modify: `crates/multipass/tests/aggregation.rs`
- Modify: `crates/multipass/src/bin/multipass-linux-client/main.rs`
- Test: transport unit and integration tests

**Interfaces:**
- Produces: dynamic `Transport`, `UplinkRegistry`, immutable `UplinkSnapshot`, `SendPolicy`, and `EnabledAggregationPolicy`.
- Consumes: Task 1 identities/scheduler and Task 2 authenticated client config.

- [ ] **Step 1: Add failing N-connection transport tests**

Use real local QUIC connections to prove:

- `Transport::from_connections` accepts one, two, and three registered uplinks;
- status is ordered and keyed by stable IDs;
- one ready uplink receives all ordinary data;
- disabled/unready uplinks receive none;
- replacing one connection generation preserves sequence state and unrelated counters;
- stale generation replacement is rejected.

- [ ] **Step 2: Run focused transport tests and confirm RED**

Verify the filter with `cargo nextest list`, then run it.

- [ ] **Step 3: Implement registry and policy types**

Store paths in stable dynamic storage with compact `PathId` lookup. Channels carry `PathId`, not wired/Wi-Fi enums. `EnabledAggregationPolicy` owns scheduler decisions; transport owns connections, probes, reliability state, and counters.

- [ ] **Step 4: Generalize probe, reader, send, retransmit, SACK broadcast, readiness, dead-path, and reconnect APIs**

All loops iterate registered paths. No per-packet string lookup or vector allocation. Connection replacement increments generation and preserves logical uplink counters.

- [ ] **Step 5: Migrate tests and Linux client**

Remove `PathKind::ALL` and fixed hello loops. The Linux client may use one explicitly configured uplink but must consume the same dynamic APIs.

- [ ] **Step 6: Run multipass tests**

```bash
cargo nextest run -p multipass
```

- [ ] **Step 7: Commit**

```bash
git add crates/multipass
git commit -m "refactor: generalize client transport to n uplinks"
```

### Task 4: Dynamic authenticated server sessions

**Files:**
- Modify: `crates/multipass-server/src/main.rs`
- Add focused modules if the main file becomes harder to reason about: `session.rs`, `auth.rs`
- Test: server unit and real-QUIC integration tests

**Interfaces:**
- Produces: dynamic per-client-epoch connection registry keyed by `UplinkId` and `PathId`.
- Consumes: authenticated identity from Task 2 and hello metadata from Task 1.

- [ ] **Step 1: Add failing server registry tests**

Prove:

- one epoch accepts one, two, and three distinct uplinks;
- a newer generation replaces only the matching uplink;
- stale/duplicate generations fail;
- conflicting `PathId` mappings fail;
- one connection failure leaves unrelated paths ready;
- scheduler and SACK broadcasts include all ready paths.

- [ ] **Step 2: Run focused server tests and confirm RED**

Use `cargo nextest list` and `cargo nextest run` with a server/session filter.

- [ ] **Step 3: Replace connection-order slot assignment**

Remove `LiveConn.path`, `PathKind::ALL`, and two-slot assertions. Register authenticated hello metadata explicitly. Atomically supersede old generations and close only the superseded connection.

- [ ] **Step 4: Generalize server scheduling and broadcast loops**

Use dynamic `PathId` scheduler state. Retain session-level send window, SACK scoreboard, reorder buffer, and epoch sequence counters.

- [ ] **Step 5: Run server tests**

```bash
cargo nextest run -p multipass-server
```

- [ ] **Step 6: Commit**

```bash
git add crates/multipass-server
git commit -m "refactor: support dynamic authenticated server paths"
```

### Task 5: macOS native underlay route resolver and route leases

**Files:**
- Create: `crates/multipass/src/bin/multipassd/underlay.rs`
- Modify: `crates/multipass/src/bin/multipassd/routes.rs`
- Modify: `crates/multipass/src/bin/multipassd/utun.rs` only for shared interface-address enumeration
- Modify: `crates/multipass/Cargo.toml` for the minimal macOS framework bindings required
- Test: deterministic resolver/lease tests with an injected network-state and route-command boundary

**Interfaces:**
- Produces: `UnderlayRouteResolver`, `UnderlayRoute`, generation-fenced reference-counted `RouteLease`, and native per-interface address/service snapshots.
- Consumes: configured interface, gateway endpoint, and source family.

- [ ] **Step 1: Read the selected macOS SDK declarations**

Verify SystemConfiguration dynamic-store keys/callbacks and route installation APIs against the installed SDK. Do not shell out for discovery when a native API provides authoritative service state.

- [ ] **Step 2: Add failing resolver tests**

Use fake native network-state snapshots to prove:

- LAN IPv4 resolves on-link;
- WAN IPv4 resolves through the service router;
- IPv6 resolves with interface scope/router;
- link-local/tunnel/loopback sources are rejected;
- no native service route means candidate ineligible;
- the utun default is never accepted as authority;
- an uplink added after full-tunnel activation resolves correctly.

- [ ] **Step 3: Run resolver tests and confirm RED**

Use focused nextest list/run filters.

- [ ] **Step 4: Implement native network-state resolver**

Read service/interface/router/address state from SystemConfiguration. Emit immutable generation-tagged snapshots. Subscribe to change notifications and provide a bounded refresh path.

- [ ] **Step 5: Add failing route-lease tests**

Prove reference counting, candidate loser cleanup, winner retention, stale-generation protection, and last-owner removal.

- [ ] **Step 6: Implement scoped route leases**

Install endpoint-specific IPv4/IPv6 scoped host routes before dialing. `routes.rs` retains tunnel address/default-route ownership; underlay route protection moves to the lease manager.

- [ ] **Step 7: Run macOS daemon route tests**

```bash
cargo nextest run -E 'package(multipass) & (test(underlay) | test(route))'
```

- [ ] **Step 8: Commit**

```bash
git add crates/multipass
git commit -m "feat: resolve late roaming underlay routes"
```

### Task 6: Endpoint racing and persistent daemon lifecycle

**Files:**
- Create: `crates/multipass/src/bin/multipassd/dialer.rs`
- Modify: `crates/multipass/src/bin/multipassd/main.rs`
- Modify: `crates/multipass/src/bin/multipassd/ipc.rs`
- Modify: `crates/multipass/src/bin/multipassd/routes.rs`
- Test: daemon state-machine, race, IPC, and pump tests

**Interfaces:**
- Produces: independent per-uplink state machines, source × endpoint racing, persistent enabled intent, dynamic status arrays.
- Consumes: config/auth, dynamic transport, and underlay route leases.

- [ ] **Step 1: Add failing uplink lifecycle tests**

Prove disabled → waiting → racing → ready → backoff transitions, network-change generation invalidation, zero-ready persistent intent, and late connection without another Connect command.

- [ ] **Step 2: Add failing endpoint-race tests**

With real local authenticated endpoints and injected route leases, prove the first authenticated winner is installed, losers close, wrong-key candidates do not win, and stale results cannot replace a newer generation.

- [ ] **Step 3: Run lifecycle/race tests and confirm RED**

Use verified nextest filters.

- [ ] **Step 4: Replace positional arguments with `--config`**

Load validated config at startup. Shared state owns ordered uplink snapshots, gateway identity, and VPN enabled/connected distinction. Remove fixed source/interface fields and two-element backoff arrays.

- [ ] **Step 5: Implement independent uplink controllers and endpoint racing**

Each enabled uplink resolves addresses/routes and races compatible endpoints. It installs at most one winner, preserves logical epoch and reliability state, and reacts immediately to native network-generation changes.

- [ ] **Step 6: Replace fixed IPC status with ordered uplink arrays**

Facet models include ID, display name, interface, configured-enabled state, runtime state, source, endpoint, RTT, counters, and bounded last error. `benchmark_topology` reuses live dynamic source data.

- [ ] **Step 7: Run daemon tests**

```bash
cargo nextest run -p multipass
```

- [ ] **Step 8: Commit**

```bash
git add crates/multipass
git commit -m "feat: race endpoints across dynamic roaming uplinks"
```

### Task 7: Dynamic Swift IPC model and menu UI

**Files:**
- Modify: `app/Sources/Multipass/DaemonProtocol.swift`
- Modify: `app/Sources/Multipass/TunnelController.swift`
- Modify: `app/Sources/Multipass/MenuBarView.swift`
- Modify: `app/README.md`
- Modify: relevant `app/Tests/MultipassTests/*.swift`

**Interfaces:**
- Produces: ordered `[UplinkSnapshot]`, stable-ID rate derivation, dynamic path rows, and enabled/waiting/connected presentation.
- Consumes: daemon IPC contract from Task 6.

- [ ] **Step 1: Add failing Swift decoding and rate tests**

Fixtures cover zero, one, two, and three uplinks; reordering by topology; counter reset on one ID without suppressing other rates; active ID changes; and enabled-but-waiting state.

- [ ] **Step 2: Run Swift tests and confirm RED**

```bash
swift test
```

Expected: decode/model failures because fixed wired/Wi-Fi fields remain.

- [ ] **Step 3: Implement dynamic Sendable snapshots**

Remove `ActivePath` and fixed counter fields. Use immutable `Sendable` values crossing from `DaemonClient` actor to the `MainActor` observable controller. Key prior samples and rate state by stable uplink ID.

- [ ] **Step 4: Render dynamic rows with stable identity**

Use `ForEach(uplinks, id: \.id)`. Preserve configuration order. Display disabled, waiting, racing/authenticating, ready, and error states without mirroring model state in view-local storage.

- [ ] **Step 5: Run Swift tests and release build**

```bash
swift test
swift build -c release
```

- [ ] **Step 6: Commit**

```bash
git add app
git commit -m "refactor: render dynamic VPN uplinks"
```

### Task 8: Installer, deployment configuration, and documentation cutover

**Files:**
- Modify: `install-mac.sh`
- Modify: `uninstall-mac.sh` only if ownership paths change
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `deploy/README.md`
- Modify private deployment source under `~/w/vixenware/vixen-central/infra/host/jax/` for server config/service arguments
- Generate: installed launchd plist and private host config from source; never edit generated/live files as the source of truth

**Interfaces:**
- Produces: preserved identities, root-owned configs, launchd `--config`, and jax authorized-client configuration.
- Consumes: Task 2 config schemas and release binaries.

- [ ] **Step 1: Add or extend installer validation oracle**

Make the installer support a non-mutating plan/validation mode that proves config paths, identity preservation, launch arguments, and zero currently connected uplinks without requiring installation.

- [ ] **Step 2: Run the oracle and confirm RED**

Expected: current script still requires two addresses and emits positional arguments.

- [ ] **Step 3: Implement identity/config preservation**

Generate identities only when absent; never replace them during reinstall. Write configs atomically with root-only permissions. Preserve operator-owned endpoint values. Launchd receives only `--config`.

- [ ] **Step 4: Update jax source configuration**

Add persistent server identity path, authorized scooter public key mapping, bind/IPv6 settings, and remove positional-only assumptions. Keep real public endpoints/prefix in private vixen-central configuration.

- [ ] **Step 5: Update public documentation**

Describe N uplinks, LAN/WAN endpoint racing, pinned mutual identity, enabled-but-offline state, and dynamic IPC. Remove dual-only and unauthenticated claims.

- [ ] **Step 6: Commit each repository**

Commit Multipass installer/docs, then commit the vixen-central deployment-source update separately.

### Task 9: Full static and automated verification

**Files:** all modified files

- [ ] **Step 1: Format**

```bash
cargo fmt --all
```

Run the Swift formatter only if the repository defines one; otherwise preserve existing style.

- [ ] **Step 2: Run all Rust tests**

```bash
cargo nextest run
```

- [ ] **Step 3: Run strict Rust checks**

```bash
cargo check --all-features --all-targets
cargo clippy --all-features --all-targets --message-format=short -- -D warnings
```

- [ ] **Step 4: Run Swift verification**

```bash
cd app
swift test
swift build -c release
```

- [ ] **Step 5: Verify removed assumptions**

Search source/docs for `PathKind`, fixed wired/Wi-Fi IPC fields, two-slot arrays, positional two-source usage, `SkipVerify`, and `with_no_client_auth`. Any remaining occurrence must be a historical statement in the superseded design or an intentional test proving rejection.

- [ ] **Step 6: Run production-path local smoke scenario**

Launch a local authenticated server and daemon/client harness with N = 1 and N = 3. Send real IP-shaped data through the transport, replace one connection generation, and observe unchanged epoch/sequence continuity.

- [ ] **Step 7: Commit verification fixes**

Commit only if verification required source changes.

### Task 10: Install, deploy, and benchmark available topologies

**Files/artifacts:** release client daemon/app, release server, scooter config/identity, jax config/identity, persisted benchmark JSON

- [ ] **Step 1: Build identified release artifacts**

Set `MULTIPASS_BUILD_COMMIT` to the actual source commit for both client and server builds. Build macOS client/app and x86_64 Linux server.

- [ ] **Step 2: Install scooter artifacts through the canonical installer**

Verify installed hashes, launchd arguments, root config permissions, identity preservation, and daemon IPC availability. No wired interface is required for installation.

- [ ] **Step 3: Deploy jax through source-owned configuration**

Install the release server and updated unit/config, restart only `multipass-server`, verify active state, and verify installed hash/build identity.

- [ ] **Step 4: Exercise zero-ready and Wi-Fi-only roaming states**

With wired links disconnected, Connect must remain enabled, Wi-Fi must authenticate through the fastest reachable jax endpoint, and status must show dynamic uplink state. Run concurrent TCP, UDP, ICMPv4, and ICMPv6 continuity traffic through a Wi-Fi connection replacement or endpoint transition that can be performed without changing unrelated network configuration.

- [ ] **Step 5: Run Wi-Fi-only benchmark**

Persist the benchmark and mechanically report raw Wi-Fi capacity, tunnel throughput, efficiency, retransmits, selected source/endpoint, build identities, errors, and restoration result.

- [ ] **Step 6: Run wired-only and two-wired benchmarks when physically available**

For each attached wired uplink independently and together, repeat the same persisted benchmark/oracle. Do not infer results while the links are disconnected.

- [ ] **Step 7: Verify installed app UI**

Open the production app, observe dynamic uplink rows and enabled/waiting/connected states, and verify the UI reflects daemon IPC without fixed wired/Wi-Fi assumptions.

- [ ] **Step 8: Record exact reachable and blocked evidence**

Report completed topologies with persisted artifact paths. Mark physically unavailable wired experiments as blocked by disconnected hardware, not as passing or failing.
