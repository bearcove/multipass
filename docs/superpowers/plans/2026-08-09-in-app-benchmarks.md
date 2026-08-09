# Multipass In-App Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production-shaped in-app benchmark suite for raw physical paths and the Multipass tunnel, with managed jax listeners, live progress, persistent labeled history, baseline comparisons, and installed scooter↔jax verification.

**Architecture:** The unprivileged Swift app launches local `iperf3` processes and owns planning, parsing, lifecycle, persistence, and presentation. The root daemon exposes authoritative topology and serializes tunnel state changes but never launches benchmark processes. Jax provides fixed systemd-managed listeners on ports 5210–5225.

**Tech Stack:** Rust 2024, Tokio, noq, newline-delimited daemon IPC, Swift 6.4, SwiftUI/AppKit on macOS 27, Swift Testing, Foundation `Process`, systemd, nftables, iperf3 JSON streaming.

## Global Constraints

- Preserve the existing daemon privilege boundary: no subprocess execution or history storage in `multipassd`.
- The app must never invoke a shell, SSH, or Git at runtime.
- Model physical paths as an ordered array with stable IDs; do not bake wired/Wi-Fi fields into benchmark code.
- Full suite parameters are fixed: TCP, four streams, ten measured seconds, three omitted seconds, one-second intervals, five-second connect timeout.
- Starting disconnected must run raw tests, connect for tunnel tests, then restore disconnected state after success, failure, or cancellation.
- No failed or partial simultaneous run may be reported as aggregate capacity.
- Persist normalized metrics and raw final iperf payloads atomically under Application Support.
- Use observable behavior tests only; do not test SwiftUI source structure.
- Rust tests use `cargo nextest run`, never `cargo test`.
- Installed scooter↔jax execution is the final acceptance oracle.

---

### Task 1: Daemon benchmark topology contract

**Files:**
- Modify: `crates/multipass/src/bin/multipassd/ipc.rs`
- Modify: `crates/multipass/src/bin/multipassd/main.rs`
- Modify: `app/Sources/Multipass/DaemonProtocol.swift`
- Modify: `app/README.md`

**Interfaces:**
- Produces Rust IPC request `{"cmd":"benchmark_topology"}`.
- Produces Swift `DaemonRequest.benchmarkTopology`.
- Produces Swift `BenchmarkTopology`, `BenchmarkPath`, and `DaemonReply.benchmarkTopology(BenchmarkTopology)`.
- `BenchmarkTopology` fields: `protocolVersion`, `serverVersion`, `underlayTarget`, optional `tunnelIPv4Target`, optional `tunnelIPv6Target`, `listenerBasePort`, `listenerCount`, ordered `paths`.

- [ ] **Step 1: Add failing Rust IPC contract tests**

Add tests that construct `Shared` with resolved interface/source fields and assert the topology reply contains:

```json
{"type":"benchmark_topology","protocol_version":1,"underlay_target":"10.0.0.5","tunnel_ipv4_target":"10.10.99.1","tunnel_ipv6_target":"fd00:99::1","listener_base_port":5210,"listener_count":16,"paths":[{"id":"wired","display_name":"Wired","interface":"en0","source_address":"192.168.1.5"},{"id":"wifi","display_name":"Wi-Fi","interface":"en1","source_address":"192.168.1.6"}]}
```

Also assert an absent optional tunnel family serializes as `null`, and the path order remains configured order.

- [ ] **Step 2: Run the selected tests and verify RED**

```bash
cargo nextest list -E 'test(ipc::tests::benchmark_topology)'
cargo nextest run -E 'test(ipc::tests::benchmark_topology)'
```

Expected: fail because the command and response do not exist.

- [ ] **Step 3: Extend Shared with immutable benchmark metadata**

Add immutable fields initialized once at daemon startup:

```rust
pub benchmark_protocol_version: u32,
pub server_version: String,
pub benchmark_listener_base_port: u16,
pub benchmark_listener_count: u16,
```

Use compile-time build identity for `server_version`; use `unknown` only when the build environment did not provide one. Reuse `TUNNEL_SERVER` and `TUNNEL_V6_SERVER` for tunnel targets.

- [ ] **Step 4: Implement topology JSON at the existing IPC boundary**

Add `benchmark_topology_json(&Shared) -> String` and route `benchmark_topology` through `handle_request`. Escape all string fields with a small JSON-string encoder rather than interpolating untrusted strings directly. Keep one response line under 4 KiB.

- [ ] **Step 5: Add Swift protocol models**

Add Codable/Sendable values matching the daemon keys exactly. `DaemonReply` must reject malformed topology rather than silently defaulting missing fields.

- [ ] **Step 6: Verify contract tests and compile both sides**

```bash
cargo nextest run -E 'test(ipc::tests::)'
cargo check --workspace --all-targets
swift build --package-path app
```

Expected: all pass without warnings.

- [ ] **Step 7: Update the documented IPC schema**

Add the request, response, field semantics, array ordering, listener-capacity invariant, and protocol-version behavior to `app/README.md`.

- [ ] **Step 8: Commit**

```bash
git add crates/multipass/src/bin/multipassd app/Sources/Multipass/DaemonProtocol.swift app/README.md
git commit -m "app: expose benchmark topology"
```

---

### Task 2: Managed jax iperf listeners

**Files:**
- Create: `../vixen-central/infra/host/jax/etc/systemd/system/iperf3-benchmark@.service`
- Modify: `../vixen-central/infra/host/jax/etc/nftables.conf`
- Modify: `../vixen-central/infra/host/jax/README.md`
- Modify: `deploy/README.md`

**Interfaces:**
- Produces listeners on TCP ports 5210–5225.
- Consumes topology defaults `listener_base_port = 5210`, `listener_count = 16`.

- [ ] **Step 1: Write the templated systemd unit**

Use an instantiated service whose instance is the port:

```ini
[Unit]
Description=Multipass benchmark iperf3 listener on port %i
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/iperf3 --server --port %i --idle-timeout 60 --server-max-duration 30
Restart=always
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service @network-io

[Install]
WantedBy=multi-user.target
```

Validate the exact sandbox against Debian's installed iperf3; remove only directives proven incompatible.

- [ ] **Step 2: Add scoped firewall admission**

Permit TCP destination ports `5210-5225` only from:

- trusted LAN source `10.10.10.0/24` on `$TRUSTED`;
- tunnel IPv4 source `10.10.99.0/24` on `$MULTIPASS`;
- tunnel IPv6 source `fd00:99::/64` on `$MULTIPASS`.

Rules must precede broader interface accepts only where needed; do not widen WAN or CI access.

- [ ] **Step 3: Validate canonical configuration locally and on jax**

Copy to `/tmp`, then run:

```bash
sudo systemd-analyze verify /tmp/iperf3-benchmark@.service
sudo nft -c -f /tmp/nftables.conf
```

Expected: both succeed before installation.

- [ ] **Step 4: Install and enable all listeners**

Install the canonical unit and nftables snapshot to live `/etc`, reload systemd and nftables, then enable/start instances `5210` through `5225`.

- [ ] **Step 5: Exercise listeners from both raw and tunnel routes**

With Multipass disconnected, run a short test bound to each physical source address against distinct ports. Connect Multipass and run short IPv4 and IPv6 tunnel tests. Verify unauthorized interfaces are not opened by the firewall change.

- [ ] **Step 6: Record live configuration**

Commit live `/etc` through etckeeper after checking the staged paths. Commit the canonical vixen-central snapshot separately.

- [ ] **Step 7: Update deployment documentation**

Document port ownership, service management, firewall scope, and verification commands in both repository locations.

- [ ] **Step 8: Commit canonical configuration**

```bash
cd ../vixen-central
git add infra/host/jax/etc/systemd/system/iperf3-benchmark@.service infra/host/jax/etc/nftables.conf infra/host/jax/README.md
git commit -m "jax: manage multipass benchmark listeners"
```

---

### Task 3: Swift benchmark domain and suite planner

**Files:**
- Modify: `app/Package.swift`
- Create: `app/Sources/Multipass/BenchmarkModels.swift`
- Create: `app/Sources/Multipass/BenchmarkPlanner.swift`
- Create: `app/Tests/MultipassTests/BenchmarkPlannerTests.swift`

**Interfaces:**
- Produces immutable Sendable values: `BenchmarkParameters`, `BenchmarkDirection`, `BenchmarkAddressFamily`, `BenchmarkRoute`, `BenchmarkTestID`, `BenchmarkInvocation`, `BenchmarkSuitePlan`.
- Produces `BenchmarkPlanner.plan(topology:parameters:) throws -> BenchmarkSuitePlan`.

- [ ] **Step 1: Add Swift Testing target**

Add `.testTarget(name: "MultipassTests", dependencies: ["Multipass"])`. Keep default MainActor isolation only where production UI needs it; pure model/planner declarations must be `nonisolated` and Sendable.

- [ ] **Step 2: Write failing planner tests**

Cover literal expected plans for:

- one physical path;
- wired + Wi-Fi;
- four paths;
- absent tunnel IPv6 target;
- insufficient listener count;
- stable IDs independent of path array index.

For two paths, assert exact order:

1. wired upload;
2. Wi-Fi upload;
3. wired download;
4. Wi-Fi download;
5. raw aggregate upload with ports 5210/5211;
6. raw aggregate download with ports 5210/5211;
7. tunnel IPv4 upload/download;
8. tunnel IPv6 upload/download.

- [ ] **Step 3: Run planner tests and verify RED**

```bash
swift test --package-path app --filter BenchmarkPlannerTests
```

Expected: fail because planner types do not exist.

- [ ] **Step 4: Implement immutable benchmark domain**

Use enums with associated stable path IDs. An aggregate invocation contains one member invocation per path and distinct ports. Parameters are fixed defaults but Codable so persisted runs retain exact values.

- [ ] **Step 5: Implement deterministic planning and validation**

Reject empty paths, duplicate path IDs, missing/invalid source addresses, listener ranges overflowing `UInt16`, and simultaneous plans with insufficient listeners. Omit only tunnel families whose targets are absent.

- [ ] **Step 6: Verify planner behavior**

```bash
swift test --package-path app --filter BenchmarkPlannerTests
swift build --package-path app
```

Expected: all planner tests pass and app compiles.

- [ ] **Step 7: Commit**

```bash
git add app/Package.swift app/Sources/Multipass/BenchmarkModels.swift app/Sources/Multipass/BenchmarkPlanner.swift app/Tests/MultipassTests/BenchmarkPlannerTests.swift
git commit -m "app: plan benchmark suites"
```

---

### Task 4: iperf discovery, streaming parser, and process runner

**Files:**
- Create: `app/Sources/Multipass/IperfDiscovery.swift`
- Create: `app/Sources/Multipass/IperfStreamParser.swift`
- Create: `app/Sources/Multipass/IperfRunner.swift`
- Create: `app/Tests/MultipassTests/Fixtures/iperf-upload.jsonl`
- Create: `app/Tests/MultipassTests/Fixtures/iperf-download.jsonl`
- Create: `app/Tests/MultipassTests/IperfStreamParserTests.swift`
- Create: `app/Tests/MultipassTests/IperfRunnerTests.swift`

**Interfaces:**
- Produces `IperfDiscovery.findExecutable() -> URL?` checking only `/opt/homebrew/bin/iperf3`, then `/usr/local/bin/iperf3`.
- Produces `IperfStreamEvent.interval(bitsPerSecond:)`, `.completed(IperfFinalResult)`, `.warning(String)`.
- Produces actor `IperfRunner.run(invocation:onSample:) async throws -> BenchmarkMeasurement` and `cancelAll() async`.

- [ ] **Step 1: Capture real JSON-stream fixtures**

Run installed iperf3 with `--json-stream-full-output --forceflush` for upload and reverse download against a controlled listener. Store representative interval and final lines as test resources, preserving every documented field used by the parser.

- [ ] **Step 2: Write failing parser tests**

Assert:

- interval throughput extraction;
- upload uses the receiver summary appropriate to observed delivered throughput;
- reverse download uses the local receiver summary;
- retransmits, bytes, stream count, RTT fields, and raw final payload are retained;
- malformed non-final lines produce warnings without losing a valid final result;
- malformed/missing final result fails the measurement.

- [ ] **Step 3: Verify parser RED**

```bash
swift test --package-path app --filter IperfStreamParserTests
```

- [ ] **Step 4: Implement incremental line parser**

Decode each JSON line into narrowly typed Codable envelopes. Do not decode into `[String: Any]`. Preserve final raw line as `Data` or UTF-8 `String` inside the normalized result.

- [ ] **Step 5: Write failing process-runner tests**

Provide a test-only executable fixture that emits interval/final lines, writes stderr, sleeps, and responds to termination. Assert:

- argument array is passed without a shell;
- stdout/stderr are drained concurrently;
- samples arrive incrementally;
- nonzero exit surfaces stderr;
- timeout terminates and reaps the child;
- cancellation terminates all simultaneous member processes;
- a failed aggregate member prevents a successful aggregate while preserving partial diagnostics.

- [ ] **Step 6: Implement actor-owned Process lifecycle**

Use `Process`, `Pipe`, and task-owned byte consumers. Build arguments directly from `BenchmarkInvocation`. Bound total runtime to warm-up + duration + startup/teardown margin. Terminate, await grace, then force-kill and reap when necessary.

- [ ] **Step 7: Implement simultaneous aggregate execution**

Launch all member processes concurrently. Sum current one-second samples by path ID. Final aggregate succeeds only when every member succeeds; normalized aggregate stores each member result.

- [ ] **Step 8: Verify parser and runner**

```bash
swift test --package-path app --filter Iperf
swift build --package-path app
```

- [ ] **Step 9: Commit**

```bash
git add app/Sources/Multipass/Iperf* app/Tests/MultipassTests
git commit -m "app: run and parse iperf benchmarks"
```

---

### Task 5: Tunnel lifecycle orchestration

**Files:**
- Modify: `app/Sources/Multipass/TunnelController.swift`
- Create: `app/Sources/Multipass/BenchmarkController.swift`
- Create: `app/Tests/MultipassTests/BenchmarkControllerTests.swift`

**Interfaces:**
- Produces explicit `TunnelController.setConnected(_:owner:) async throws` and benchmark ownership state.
- Produces `BenchmarkController.startFullSuite()`, `cancel()`, `rerun(_:)`, live state, and completed in-memory run.
- Consumes planner, runner, daemon topology, and tunnel status.

- [ ] **Step 1: Write failing lifecycle tests**

Use protocol-backed real orchestration with deterministic fake daemon/runner boundaries. Cover:

- initially disconnected: raw → connect → tunnel → disconnect;
- initially connected: no disconnect at end;
- raw failure continues independent tests;
- connect failure marks tunnel tests failed and restores;
- cancellation reaps runner and restores;
- daemon unavailable during restoration records a distinct restoration error;
- menu toggle is disabled while benchmark owns lifecycle;
- rerun replaces a prior result only after success.

- [ ] **Step 2: Verify lifecycle RED**

```bash
swift test --package-path app --filter BenchmarkControllerTests
```

- [ ] **Step 3: Extract an explicit tunnel state transition API**

Replace toggle-only internals with idempotent desired-state transitions. Keep status as source of truth. Serialize ordinary UI and benchmark transitions through one owner-aware mechanism; no mirrored connection state.

- [ ] **Step 4: Implement suite state machine**

Use one owned `Task`. States must distinguish loading topology, raw measurement, connecting, tunnel measurement, restoring, completed, cancelled, and failed. Update MainActor only with normalized one-second samples and state changes.

- [ ] **Step 5: Implement guaranteed restoration**

Capture initial connected state before work. A `defer`-equivalent async restoration phase must run after success, error, or cancellation. Wait for observed daemon status, not fixed sleeps.

- [ ] **Step 6: Verify lifecycle and existing tunnel behavior**

```bash
swift test --package-path app --filter BenchmarkControllerTests
swift test --package-path app
swift build --package-path app
```

- [ ] **Step 7: Commit**

```bash
git add app/Sources/Multipass/TunnelController.swift app/Sources/Multipass/BenchmarkController.swift app/Tests/MultipassTests/BenchmarkControllerTests.swift
git commit -m "app: orchestrate benchmark lifecycle"
```

---

### Task 6: Persistent history, baselines, and report generation

**Files:**
- Create: `app/Sources/Multipass/BenchmarkStore.swift`
- Create: `app/Sources/Multipass/BenchmarkComparison.swift`
- Create: `app/Sources/Multipass/BenchmarkReport.swift`
- Create: `app/Tests/MultipassTests/BenchmarkStoreTests.swift`
- Create: `app/Tests/MultipassTests/BenchmarkComparisonTests.swift`
- Create: `app/Tests/MultipassTests/BenchmarkReportTests.swift`

**Interfaces:**
- Produces actor `BenchmarkStore` with `loadIndex`, `loadRuns`, `saveRun`, `renameRun`, `selectBaseline`.
- Produces compatibility-aware signed deltas.
- Produces deterministic Markdown report text.

- [ ] **Step 1: Write failing atomic-store tests**

Use a temporary directory injected into the store. Assert one-file-per-run layout, atomic replacement, index ordering, selected baseline persistence, corrupt-file isolation, unknown-schema rejection, and user-label updates that do not mutate measurement data.

- [ ] **Step 2: Write failing comparison tests**

Assert literal absolute/percentage deltas, incompatible identities, matching physical path IDs, aggregate path-set mismatch annotation, and absent deltas when either result failed.

- [ ] **Step 3: Write failing report tests**

Assert a complete Markdown fixture containing build identities, topology, parameters, Gbit/s, retransmits, signed deltas, efficiency, failures/skips, and restoration errors.

- [ ] **Step 4: Verify RED**

```bash
swift test --package-path app --filter BenchmarkStoreTests
swift test --package-path app --filter BenchmarkComparisonTests
swift test --package-path app --filter BenchmarkReportTests
```

- [ ] **Step 5: Implement atomic Codable storage**

Use Application Support by default and injected directory for tests. Write temporary sibling file, synchronize/close, then replace/rename. Do not persist in-progress or cancelled runs as completed history.

- [ ] **Step 6: Implement normalized comparisons and report**

Formatting belongs outside SwiftUI. Use stable decimal formatting and explicit signs. Do not construct JSON manually; persisted JSON uses `JSONEncoder`/`JSONDecoder`.

- [ ] **Step 7: Verify storage and reporting**

```bash
swift test --package-path app --filter BenchmarkStoreTests
swift test --package-path app --filter BenchmarkComparisonTests
swift test --package-path app --filter BenchmarkReportTests
swift test --package-path app
```

- [ ] **Step 8: Commit**

```bash
git add app/Sources/Multipass/BenchmarkStore.swift app/Sources/Multipass/BenchmarkComparison.swift app/Sources/Multipass/BenchmarkReport.swift app/Tests/MultipassTests
git commit -m "app: persist and compare benchmarks"
```

---

### Task 7: Benchmark window and menu integration

**Files:**
- Modify: `app/Sources/Multipass/MultipassApp.swift`
- Modify: `app/Sources/Multipass/MenuBarView.swift`
- Create: `app/Sources/Multipass/BenchmarkWindow.swift`
- Create: `app/Sources/Multipass/BenchmarkHistorySidebar.swift`
- Create: `app/Sources/Multipass/BenchmarkResultsView.swift`
- Create: `app/Sources/Multipass/BenchmarkLiveChart.swift`

**Interfaces:**
- Produces a resizable `Window` scene addressable by ID.
- Menu `Benchmark…` opens/focuses the scene.
- Window consumes `BenchmarkController` only; formatting and comparison logic remain outside views.

- [ ] **Step 1: Add shared benchmark controller ownership**

Own one `BenchmarkController` at app scope alongside `TunnelController`. Inject the same instances into menu and benchmark window. The benchmark task survives window closure.

- [ ] **Step 2: Add menu entry**

Add `Benchmark…` above the footer divider. Use `openWindow(id:)`. Disable the tunnel toggle while a benchmark owns lifecycle and show the reason in accessible help text.

- [ ] **Step 3: Build native split-view hierarchy**

History sidebar: New Benchmark, completed runs newest first, editable user label, baseline selection, status. Detail: metadata header, Run Full Suite, grouped result matrix, efficiency, reruns, Copy Report.

- [ ] **Step 4: Build running presentation**

Show suite progress, current measurement, live aggregate throughput, bounded one-second chart, completed rows, remaining measurements, and Cancel. Use monospaced digits, semantic colors plus signed text, and no decorative card grid.

- [ ] **Step 5: Implement clipboard and accessibility behavior**

Copy Report writes the generated Markdown to `NSPasteboard`. Every result exposes route, direction, status, throughput, and delta as combined accessibility text. Graph has a textual current/peak summary.

- [ ] **Step 6: Compile and run the app**

```bash
swift build --package-path app
```

Launch the built app and use Computer Use to verify menu opening, resizable window behavior, disconnected prerequisite state, history selection, keyboard focus, and native light/dark appearance.

- [ ] **Step 7: Commit**

```bash
git add app/Sources/Multipass
git commit -m "app: add benchmark window"
```

---

### Task 8: Installed build identity and packaging

**Files:**
- Modify: `install-mac.sh`
- Modify: `app/Sources/Multipass/Info.plist`
- Create or modify: `build.rs` files for daemon/server crates as required
- Modify: `deploy/README.md`

**Interfaces:**
- Produces installed app Info.plist key `MultipassGitCommit`.
- Produces daemon/server compile-time version strings surfaced by topology.

- [ ] **Step 1: Add build-identity behavior tests where pure**

Test app bundle metadata parsing with injected dictionaries and daemon fallback formatting with explicit environment values. Do not test source text.

- [ ] **Step 2: Embed app identity during installation**

The installer copies the source plist to a temporary plist, writes the current exact commit through `/usr/libexec/PlistBuddy`, then installs it. Runtime never invokes Git.

- [ ] **Step 3: Embed Rust binary identities**

Use build-script environment values or an existing repository pattern. Preserve reproducibility; rebuild when the commit identity changes.

- [ ] **Step 4: Verify installed metadata and topology**

Build release app/client/server, install, then inspect `/Applications/Multipass.app/Contents/Info.plist` and the daemon topology response. Values must match the installed artifacts.

- [ ] **Step 5: Commit**

```bash
git add install-mac.sh app/Sources/Multipass/Info.plist crates deploy/README.md
git commit -m "build: embed multipass identities"
```

---

### Task 9: Full verification and production oracle

**Files:**
- Modify: `README.md`
- Modify: `app/README.md`
- Modify: `docs/superpowers/specs/2026-08-09-in-app-benchmarks-design.md` only if implementation reveals an approved-contract correction

**Interfaces:**
- Consumes all previous tasks.
- Produces installed scooter↔jax benchmark evidence and final user documentation.

- [ ] **Step 1: Run complete source gates**

```bash
cargo fmt --all
cargo clippy --all-features --all-targets --message-format=short -- -D warnings
cargo nextest run
cargo build --release -p multipass --bin multipassd
cargo zigbuild --target x86_64-unknown-linux-gnu --release -p multipass-server
swift test --package-path app
swift build --package-path app -c release
```

Expected: no failures or warnings.

- [ ] **Step 2: Deploy installed artifacts**

Install the release daemon and `/Applications/Multipass.app`; deploy/restart the release server. Confirm byte checksums and build identities.

- [ ] **Step 3: Run complete suite from disconnected state**

Using the installed app, observe:

- every physical path upload/download;
- simultaneous aggregate upload/download on distinct listener ports;
- tunnel IPv4 upload/download;
- tunnel IPv6 upload/download;
- retransmit counts and raw final payload retention;
- automatic return to disconnected state.

- [ ] **Step 4: Verify history and comparison**

Quit/reopen the app, confirm persistence, run a second suite, select the first baseline, verify signed deltas and compatibility annotations, rename a run, and rerun one measurement atomically.

- [ ] **Step 5: Verify cancellation restoration**

Start disconnected, cancel during simultaneous execution, confirm all local iperf processes exit and the tunnel returns to disconnected. Repeat from initially connected and confirm it remains connected.

- [ ] **Step 6: Verify Copy Report evidence**

Copy the report and compare visible throughput, retransmits, identities, deltas, efficiency, and errors with the Markdown clipboard payload.

- [ ] **Step 7: Visual/accessibility QA with Computer Use**

Verify the real installed app in light and dark appearance, narrow/minimum window size, keyboard focus, VoiceOver-compatible labels through the accessibility tree, and live chart updates without menu-panel overlap.

- [ ] **Step 8: Update status documentation**

Document the benchmark workflow, listener management, persisted-history location, fixed parameters, and the exact measured installed results. Do not claim throughput or failover improvements beyond observed evidence.

- [ ] **Step 9: Commit final documentation**

```bash
git add README.md app/README.md docs
git commit -m "docs: document in-app benchmarks"
```
