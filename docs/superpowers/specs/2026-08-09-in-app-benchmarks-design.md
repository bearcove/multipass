# Multipass In-App Benchmarks Design

**Date:** 2026-08-09
**Status:** Approved design, pending written-spec review
**Goal:** Make repeatable scooter-to-jax raw-path and tunnel throughput measurements directly from the Multipass app, with live progress, persistent labeled history, and baseline comparisons suitable for scheduler optimization.

## Context

Multipass currently needs manually coordinated `iperf3` commands, SSH-started listeners, temporary files, and ad hoc result extraction. This makes it unnecessarily difficult to answer the questions that matter during transport work:

- What can each physical underlay deliver by itself?
- What is the simultaneous aggregate capacity of all available underlays?
- What does the tunnel deliver in each direction and address family?
- What percentage of raw capacity reaches the tunnel?
- Did a particular client/server build improve or regress those measurements?

The current transport has two fixed paths, wired Ethernet and Wi-Fi. The benchmark model must not repeat that limitation: it must represent an ordered array of physical paths so the UI and runner remain valid when the transport is generalized to $N$ paths.

The benchmark feature is diagnostic tooling. It must not move process execution, result storage, or benchmark policy into the privileged dataplane daemon.

## Decisions

1. The macOS app owns unprivileged `iperf3` client processes, streaming output parsing, suite orchestration, cancellation, persistence, and presentation.
2. `multipassd` exposes authoritative topology and tunnel metadata over its existing Unix-socket IPC. It does not launch subprocesses.
3. Jax runs fixed systemd-managed `iperf3` listeners on a reserved port range. The app never uses SSH or stores credentials.
4. The primary action runs a complete fixed suite. Every individual measurement can also be rerun.
5. Completed suites are persisted locally with automatic build labels, editable human labels, raw final `iperf3` payloads, and normalized metrics.
6. Starting a suite while disconnected automatically connects for tunnel measurements and restores the original disconnected state afterward, including after cancellation or failure.
7. The benchmark UI lives in a normal resizable window opened from the menu panel. The existing 292-point menu panel remains a tunnel-status surface.

## Architecture

```text
BenchmarkWindow
    |
    v
BenchmarkController (@Observable, MainActor)
    |-- BenchmarkPlanner          pure suite planning
    |-- IperfRunner actor         Process lifecycle + JSON stream parsing
    |-- BenchmarkStore actor      Application Support persistence
    |-- TunnelController          connection state transition API
    `-- DaemonClient actor        topology/status IPC

multipassd
    `-- benchmark_topology IPC response

jax
    `-- systemd-managed iperf3 listeners on reserved ports
```

### Privilege boundary

The app remains unprivileged. It may:

- launch the locally installed `iperf3` binary;
- bind clients to source addresses or interfaces already owned by the logged-in host;
- read/write its Application Support directory;
- request tunnel state transitions through the existing daemon socket.

Only `multipassd` continues to own utun configuration, routes, QUIC connections, and tunnel state. Jax listener installation is a deployment operation tracked with the server configuration, not an app action.

## Daemon topology contract

Add a request:

```json
{"cmd":"benchmark_topology"}
```

The response is a single newline-delimited JSON object:

```json
{
  "type":"benchmark_topology",
  "protocol_version":1,
  "server_version":"<build identity>",
  "underlay_target":"10.10.10.1",
  "tunnel_ipv4_target":"10.10.99.1",
  "tunnel_ipv6_target":"fd00:99::1",
  "listener_base_port":5210,
  "listener_count":16,
  "paths":[
    {
      "id":"wired",
      "display_name":"Wired",
      "interface":"en17",
      "source_address":"10.10.10.171"
    },
    {
      "id":"wifi",
      "display_name":"Wi-Fi",
      "interface":"en0",
      "source_address":"10.10.10.169"
    }
  ]
}
```

### Contract rules

- `paths` is an array, never fixed wired/Wi-Fi fields.
- `id` is stable within a daemon configuration and suitable for persisted result identity.
- `display_name` is user-facing.
- `interface` and `source_address` are the exact values the daemon resolved and uses for the underlay.
- `underlay_target` is reachable without entering the tunnel.
- `tunnel_ipv4_target` and `tunnel_ipv6_target` are the server-side tunnel addresses. Either tunnel target may be absent if that family is unsupported.
- `listener_base_port ..< listener_base_port + listener_count` is reserved for benchmark listeners.
- `listener_count` must be at least `max(paths.count, 1)`. The app rejects simultaneous-path planning when there are not enough distinct listeners.
- `protocol_version` versions this benchmark contract independently from the QUIC wire protocol.
- `server_version` identifies the installed multipass-server build. If the server cannot yet report a build identity directly, deployment supplies it to `multipassd`; the app must not infer it from local source state.

The existing `status`, `connect`, and `disconnect` messages remain unchanged.

## Jax listener deployment

Reserve TCP ports `5210` through `5225` for sixteen persistent listeners. Each listener is an independent `iperf3 --server` process so simultaneous physical-path tests never contend for a single iperf control server.

Use one templated systemd unit, instantiated once per port. Required properties:

- starts at boot;
- restarts on failure;
- listens on jax's LAN and tunnel addresses through the wildcard bind;
- has an idle timeout and maximum test duration so abandoned clients cannot retain a worker indefinitely;
- logs to journald;
- is permitted by jax's input firewall only from the LAN and Multipass tunnel subnets;
- is declared in the canonical jax configuration under `vixen-central/infra/host/jax`, not only edited live.

Port allocation is deterministic:

- a single-path or tunnel test uses `listener_base_port`;
- simultaneous path index $i$ uses `listener_base_port + i`;
- only one benchmark suite runs in an app process at a time;
- the current deployment has one client, so cross-client listener arbitration is outside scope.

## Local iperf discovery

The installed app has a deliberately minimal environment and must not depend on shell `PATH` lookup. It checks these executable locations in order:

1. `/opt/homebrew/bin/iperf3`
2. `/usr/local/bin/iperf3`

If neither is executable, the benchmark window shows an actionable prerequisite and disables Run:

> iperf3 is required. Install it with Homebrew: `brew install iperf3`.

The selected binary's `--version` output is captured once per suite and stored in run metadata.

## Benchmark model

### Test identity

A measurement has these independent dimensions:

- route: `.physical(pathID)`, `.physicalAggregate`, or `.tunnel`
- direction: `.upload` or `.download`
- address family: `.ipv4` or `.ipv6`
- execution: `.single` or `.simultaneousMember(pathID)`

Normalized identities must not encode array positions. Persisted physical results refer to stable path IDs.

### Fixed parameters

Every TCP measurement uses:

- four parallel streams;
- ten measured seconds;
- three omitted warm-up seconds;
- one-second reporting intervals;
- JSON streaming with full final output;
- a five-second connect timeout;
- explicit IPv4 or IPv6 selection;
- explicit source binding for physical-path tests;
- reverse mode for download tests.

Equivalent arguments:

```text
--client <target>
--port <port>
--parallel 4
--time 10
--omit 3
--interval 1
--connect-timeout 5000
--json-stream-full-output
--forceflush
--version4 | --version6
--bind <source-address>%<interface>    # physical tests only
--reverse                              # download only
```

The runner invokes `Process` directly with an argument array. It never invokes a shell.

### Full suite order

Given topology paths $P_0 ... P_n$:

1. For each physical path, IPv4 upload.
2. For each physical path, IPv4 download.
3. All physical paths simultaneously, IPv4 upload, one listener per path.
4. All physical paths simultaneously, IPv4 download, one listener per path.
5. Ensure the tunnel is connected and healthy.
6. Tunnel IPv4 upload.
7. Tunnel IPv4 download.
8. Tunnel IPv6 upload when an IPv6 target exists.
9. Tunnel IPv6 download when an IPv6 target exists.
10. Restore the initial tunnel state.

Sequential single-path tests establish individual capacities. Simultaneous tests establish actual concurrent raw capacity; the app must not substitute the arithmetic sum of sequential tests for this measurement.

Tunnel tests intentionally do not bind to the utun interface. Full-tunnel routing must select the tunnel exactly as ordinary application traffic would.

### Per-test reruns

Every completed, failed, or skipped result row exposes Rerun. A rerun:

- uses the suite's captured topology and parameters;
- performs any required connection transition;
- replaces that result in the selected suite only after the new measurement completes;
- retains the previous result if the rerun fails or is cancelled;
- updates normalized summaries and persistence atomically.

A physical aggregate row reruns all of its simultaneous member processes as one measurement.

## Tunnel lifecycle

The controller captures `initiallyConnected` before starting work.

### Initially disconnected

1. Run all raw physical tests while disconnected.
2. Send `connect`.
3. Poll status until `connected == true`, at least one path is live, and tunnel targets answer through `iperf3` control connection setup.
4. Run tunnel tests.
5. Send `disconnect` in a guaranteed restoration phase.
6. Poll until disconnected before declaring the suite finished.

### Initially connected

- Preserve the connected state throughout the suite.
- Raw tests remain explicitly source-bound, so they bypass the tunnel through the underlay host route.
- Do not disconnect after completion.

### Restoration invariant

After success, cancellation, or any thrown error, the tunnel's connected/disconnected state must equal the state captured at suite start unless the daemon becomes unavailable. If restoration fails, the run records a prominent restoration error distinct from individual benchmark failures.

The app serializes benchmark transitions and ordinary menu-panel connect/disconnect commands. While a suite owns tunnel lifecycle, the menu toggle is disabled and explains that a benchmark is running.

## Process lifecycle and streaming

`IperfRunner` is an actor with one owned process per single test and one process per path for simultaneous tests.

For each process:

- capture stdout and stderr separately;
- consume both pipes continuously to avoid blocking on a full pipe;
- split stdout into newline-delimited JSON events;
- parse interval events into live bits-per-second samples;
- parse the final event into the retained raw payload and normalized result;
- surface stderr when the process exits unsuccessfully;
- impose a total timeout of warm-up + measured duration + bounded startup/teardown margin;
- on cancellation, send termination, wait for exit, then force-kill only if it does not stop within the bounded grace period;
- reap every child before returning.

For a simultaneous aggregate measurement, live throughput is the sum of the most recent interval sample from each active member. Final aggregate throughput is the sum of each successful member's matching sender/receiver summary. A missing or failed member makes the aggregate measurement failed; partial member results remain available for diagnosis but are not presented as a successful aggregate capacity.

## Result normalization

For each successful measurement, store:

- bits per second;
- transferred bytes;
- retransmits when reported;
- mean RTT and maximum RTT when reported;
- sender/receiver role used for the throughput value;
- per-stream count;
- start and end timestamps;
- raw final JSON payload;
- for aggregate tests, all member results keyed by path ID.

The summary derives:

- best raw single-path upload/download;
- simultaneous raw aggregate upload/download;
- tunnel IPv4 upload/download;
- tunnel IPv6 upload/download;
- tunnel efficiency per direction:

$$
\text{efficiency} = \frac{\text{tunnel throughput}}{\text{simultaneous raw aggregate throughput}} \times 100\%.
$$

Efficiency is absent rather than zero when the corresponding raw aggregate or tunnel result failed.

## Persistence

Store one file per completed suite under:

```text
~/Library/Application Support/Multipass/Benchmarks/<run-id>.json
```

Store lightweight ordering and selected-baseline metadata in:

```text
~/Library/Application Support/Multipass/Benchmarks/index.json
```

### Run record

A persisted run includes:

- schema version;
- stable UUID;
- automatic label;
- optional user label;
- start/end timestamps;
- completion state and restoration error;
- app build commit;
- daemon/server versions;
- benchmark protocol version;
- iperf version;
- complete captured topology;
- exact benchmark parameters;
- initial tunnel state;
- ordered result records;
- raw final iperf payloads.

The automatic label is the local date/time plus a short installed commit, for example `2026-08-09 10:24 · 55114cb`. The user label is additive and editable; editing it never rewrites measurement data.

Persistence is atomic: write a temporary file in the same directory, synchronize/close it, then rename over the destination. A suite is persisted after restoration completes. In-progress state is UI-only and is not loaded as a completed historical run after an app crash.

Unknown future schema versions are shown as unsupported rather than partially decoded. Corrupt individual files are skipped and surfaced as history errors without preventing valid runs from loading.

## Installed build identity

The build/install flow embeds the current Git commit into the installed app's `Info.plist` under a Multipass-specific key. The app reads only installed bundle metadata; it never shells out to Git at runtime.

The daemon and server binaries expose build identity through compile-time environment values. Deployment must install binaries and metadata from the same build invocation. A dirty working tree may be represented by a `-dirty` suffix when the build tooling can prove it; otherwise the exact commit remains the required minimum identity.

## Interface design

### Menu panel

Add a `Benchmark…` button above the footer divider. It opens or focuses the benchmark window. The menu panel does not embed run details.

### Benchmark window

Use a resizable macOS utility window with a minimum content size sufficient for the result matrix. The window has two regions:

#### History sidebar

- New Benchmark action.
- Completed runs ordered newest first.
- Automatic label and optional human label.
- Status indicator for complete or completed-with-errors.
- Baseline selection control.
- Delete is outside this feature; retained runs are not removed through the first interface.

#### Detail area

Idle/completed state:

- build/topology metadata header;
- prominent Run Full Suite button;
- result matrix grouped into Physical Paths, Raw Aggregate, Tunnel IPv4, and Tunnel IPv6;
- Upload and Download columns;
- throughput, delta against baseline, and status per row;
- tunnel-efficiency summary;
- Rerun action per measurement;
- Copy Report action.

Running state:

- suite progress count;
- current measurement name and phase;
- live aggregate throughput number;
- compact live history graph using bounded one-second samples;
- remaining planned measurements;
- completed result rows updating in place;
- Cancel action.

Use native macOS controls, semantic colors, monospaced digits for measurements, and no decorative card grid. Results and comparisons carry the hierarchy.

### Deltas

When a compatible baseline is selected, display absolute throughput delta and percentage delta. Compatibility requires the same measurement identity and direction. A changed path set does not invalidate tunnel comparisons, but physical per-path comparisons require matching path IDs and aggregate comparisons clearly show when the member path set differs.

Regressions and improvements use both color and signed text; color is never the only signal.

### Copy Report

Copy a Markdown report containing:

- run label and IDs;
- app/daemon/server/iperf versions;
- topology and test parameters;
- result table with Gbit/s, retransmits, and baseline deltas;
- tunnel-efficiency values;
- failures, skips, and restoration errors.

The report is produced from normalized values, not by concatenating raw JSON. It is suitable for pasting into an issue or agent conversation.

## Error behavior

| Failure | Behavior |
| --- | --- |
| `iperf3` missing | Disable Run; show exact Homebrew prerequisite. |
| Daemon unavailable before start | Disable full suite; history remains available. |
| Topology invalid or too few listeners | Stop before launching tests; show contract error. |
| One physical path source is unavailable | Record dependent single and aggregate tests failed; continue independent paths and tunnel tests. |
| One iperf listener refuses connection | Record that measurement failed; continue independent tests. |
| Connect transition fails | Raw results remain; tunnel tests fail as a group; attempt state restoration. |
| Tunnel family absent | Mark that family's tunnel tests skipped, not failed. |
| Process timeout | Terminate/reap process; record timed-out result. |
| User cancellation | Stop/reap active processes, skip remaining tests, restore initial tunnel state, retain the run as cancelled only in the current UI; do not add it to completed history. |
| Persistence failure | Keep completed result visible in memory and show save error; never claim it is in history. |
| State restoration failure | Persist completed measurements with a prominent run-level restoration error. |

## Concurrency and ownership

- `BenchmarkController` is `@MainActor` and owns presentation state plus one suite task.
- `IperfRunner` is an actor and owns all child-process handles and cancellation.
- `BenchmarkStore` is an actor and owns filesystem access.
- Parsed event and persisted model values are immutable `Sendable` structs/enums.
- The suite task is explicit, cancellable, and joined before a replacement suite starts.
- UI closure does not cancel a running suite; the app owns the task. App termination cancels and restores where the process lifecycle permits.
- High-frequency process bytes never cross onto `MainActor`; only normalized one-second samples and state transitions do.

## Verification

### Rust contract tests

- `benchmark_topology` returns the documented discriminator and fields.
- Physical paths serialize in configured order as an array.
- Missing optional tunnel IPv6 is represented correctly.
- Unknown commands still return the existing error response.

### Swift behavior tests

Use Swift Testing in a new test target for pure and actor-isolated behavior:

- planner emits the exact suite for one, two, and $N$ paths;
- planner allocates distinct simultaneous listener ports and rejects insufficient listener capacity;
- IPv6 tunnel tests are omitted only when the topology lacks an IPv6 target;
- interval and final JSON-stream fixtures normalize upload/download values correctly;
- malformed lines and stderr failures produce typed measurement failures;
- simultaneous member values sum correctly and one failed member prevents a successful aggregate;
- cancellation reaps processes and invokes restoration;
- initially disconnected, initially connected, connection failure, and cancellation all satisfy the restoration invariant;
- run records round-trip through the store atomically;
- baseline deltas compare only compatible identities;
- Copy Report contains the normalized evidence needed for diagnosis.

Tests must exercise observable planner, parser, lifecycle, persistence, and report contracts. They must not assert SwiftUI view structure or source text.

### Production oracle

On the installed scooter↔jax deployment:

1. Verify all managed jax listeners are active and firewall-scoped.
2. Install app and daemon builds with visible build identities.
3. Start disconnected and run one full suite.
4. Observe single-path upload/download rows for every physical path.
5. Observe simultaneous raw aggregate upload/download rows using distinct listeners.
6. Observe IPv4 and IPv6 tunnel upload/download rows.
7. Verify the tunnel returns to disconnected state.
8. Reopen the app and verify the completed run persists.
9. Run a second suite, select the first as baseline, and verify signed deltas.
10. Rerun one measurement and verify atomic replacement.
11. Cancel a suite during simultaneous testing and verify all local processes exit and the initial tunnel state is restored.
12. Copy the report and verify its numbers match the visible normalized results.

The installed production run, not preview rendering or unit tests alone, is the acceptance oracle.

## Out of scope

- Generalizing the Multipass transport itself from two paths to $N$ paths.
- UDP, bidirectional, latency-only, packet-loss, or public-internet speed tests.
- Remote benchmark execution through SSH.
- Launching `iperf3` from the root daemon.
- Multi-client listener arbitration or authentication.
- Cloud synchronization or automatic deletion of benchmark history.
- Editing benchmark parameters in the first interface.
- Treating a failed or partial simultaneous run as aggregate capacity.
