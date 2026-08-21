# Multipass (menubar app)

SwiftUI menubar app for multipass — an N-uplink roaming VPN.
macOS 27 only, SwiftPM executable, no sandbox, no root: the app is a thin UI
over the privileged `multipassd` LaunchDaemon, which owns the utun device and
dynamic authenticated QUIC uplinks.

```
swift build        # produces .build/debug/Multipass
```

## UI structure

| File | Role |
| --- | --- |
| `MultipassApp.swift` | `@main` App, single `MenuBarExtra` (`.window` style). Menubar icon is a state-reflecting SF Symbol: filled multipath glyph when connected, outline when disconnected, `network.slash` when the daemon is unreachable, animated arrows during a failover flash. |
| `MenuBarView.swift` | The panel: persistent VPN intent and readiness, ordered dynamic uplink rows with runtime state, source/endpoint diagnostics, RTT and rates, ACTIVE badge, failover banner, aggregate counters/rates, prominent Connect/Disconnect toggle (`d` shortcut), benchmark controls, Launch-at-Login toggle, Quit (`q`). |
| `TunnelController.swift` | MainActor `@Observable` model. Polls status once per second, serializes connect/disconnect commands by persistent `enabled` intent, preserves daemon uplink order, derives aggregate and per-ID throughput rates from cumulative counters, and raises the failover flash when `active_uplink_id` changes while connected. |
| `DaemonClient.swift` | POSIX unix-socket client (actor). Lazy connect, one retry on a stale connection, 2s send/recv timeouts, `SO_NOSIGPIPE`. |
| `DaemonProtocol.swift` | Codable encoding of the IPC schema below. |
| `LaunchAtLogin.swift` | `SMAppService.mainApp` wrapper (same pattern as baratheon). |

## IPC contract (what `multipassd` must implement)

**Transport:** unix domain socket, `SOCK_STREAM`, at `/var/run/multipassd.sock`.
The daemon runs as root; the socket MUST be connectable by the logged-in user
(mode `0666`, or a group the user is in).

**Framing:** newline-delimited JSON. The client sends exactly one request
object followed by `\n`; the daemon replies with exactly one response object
followed by `\n`. Multiple sequential requests on one connection are allowed
(keep-alive). The client may also drop and reconnect between requests — the
daemon MUST handle short-lived connections. If the daemon closes an idle
connection, the client transparently reconnects and retries once.

### Requests (client → daemon)

| JSON | Meaning |
| --- | --- |
| `{"cmd":"status"}` | Query tunnel status. Always answered, connected or not. |
| `{"cmd":"connect"}` | Persistently enable the VPN and begin bringing configured uplinks online. |
| `{"cmd":"disconnect"}` | Disable the VPN and tear down the logical tunnel and uplink connections. |
| `{"cmd":"benchmark_topology"}` | Query authoritative underlay paths, tunnel targets, and the reserved jax listener range. |

Unknown `cmd` values MUST be answered with a `type:"error"` reply.

### Responses (daemon → client)

**Status** — the only reply to `{"cmd":"status"}`:

```json
{"type":"status","enabled":true,"connected":true,"active_uplink_id":"wifi","tx":123456,"rx":789012,"uplinks":[{"id":"desk-ethernet","display_name":"Desk Ethernet","interface":"en17","configured_enabled":true,"state":"waiting_for_address","ready":false,"source_address":null,"gateway_endpoint":null,"rtt_ms":null,"tx":0,"rx":0,"last_error":null},{"id":"wifi","display_name":"Wi-Fi","interface":"en0","configured_enabled":true,"state":"ready","ready":true,"source_address":"192.0.2.10","gateway_endpoint":"[2001:db8::10]:51823","rtt_ms":18.4,"tx":123456,"rx":789012,"last_error":null}]}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | `"status"` | Discriminator. |
| `enabled` | bool | Persistent VPN intent. Connect converges when this becomes true even if no uplink is ready; Disconnect converges when it becomes false. |
| `connected` | bool | At least one mutually authenticated uplink is ready and the logical tunnel is active. May remain false while `enabled` is true. |
| `active_uplink_id` | string \| null | Stable ID of the most recent first-delivery uplink. null without a ready delivery path. A change while `connected` stays true triggers the menubar failover flash. |
| `tx` | u64 | Cumulative logical-tunnel payload bytes sent for the current epoch. The app derives aggregate rate from consecutive samples and treats a decrease as a reset. |
| `rx` | u64 | Cumulative logical-tunnel payload bytes received for the current epoch. Same rate/reset semantics. |
| `uplinks` | array | Every configured uplink in configuration order. IDs are stable and unique. |

Each `uplinks` element has exactly these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Stable uplink identity used for row identity, rate history, active selection, and failover. |
| `display_name` | string | User-facing configured name. |
| `interface` | string | Resolved interface name. |
| `configured_enabled` | bool | Whether root-owned configuration allows this uplink to participate. |
| `state` | string | Dynamic runtime state such as `disabled`, `waiting_for_address`, `racing_endpoints`, `authenticating`, `ready`, or an error state. |
| `ready` | bool | This uplink has a mutually authenticated connection ready for tunnel traffic. |
| `source_address` | string \| null | Selected source address, or null while unavailable. |
| `gateway_endpoint` | string \| null | Selected gateway socket endpoint, or null before selection. |
| `rtt_ms` | number \| null | Smoothed RTT for this uplink, or null when unknown. |
| `tx` | u64 | Cumulative physical-path payload bytes sent, including retransmissions. |
| `rx` | u64 | Cumulative physical-path payload bytes received before tunnel deduplication. |
| `last_error` | string \| null | Concise routing/authentication/runtime error without secrets. |

Per-uplink counters are logically monotonic across connection-generation
replacement. The app derives rates independently by stable `id`, so a reset or
new sample for one uplink never suppresses another uplink's rate.

**Benchmark topology** — reply to `{"cmd":"benchmark_topology"}`:

```json
{"type":"benchmark_topology","protocol_version":2,"daemon_version":"<multipassd commit>","server_version":"<authenticated multipass-server commit or unknown while disconnected>","underlay_target":"10.10.10.1","tunnel_ipv4_target":"10.10.99.1","tunnel_ipv6_target":"fd00:99::1","listener_base_port":5210,"listener_count":16,"paths":[{"id":"desk-ethernet","display_name":"Desk Ethernet","interface":"en17","source_address":null},{"id":"wifi","display_name":"Wi-Fi","interface":"en0","source_address":"192.0.2.10"}]}
```

`paths` is ordered and uses stable IDs. `interface` is the configured/resolved
interface and `source_address` is nullable. A configured path with null
`source_address` remains in the ordered topology but is unavailable for a
physical benchmark; tunnel benchmarks remain valid. Either tunnel target may
be null when that family is unsupported. The half-open listener range is
`listener_base_port ..< listener_base_port + listener_count`; simultaneous
tests require at least one distinct listener per currently benchmarkable path.
`protocol_version` versions this control contract independently from the QUIC
wire protocol. `daemon_version` identifies the installed client daemon.
`server_version` identifies the authenticated server learned through the live
QUIC handshake and is `unknown` while disconnected.

**OK** — reply to successful connect/disconnect:

```json
{"type":"ok"}
```

**Error** — reply to a failed command or unknown request:

```json
{"type":"error","message":"already connected"}
```

`message` is shown to the user verbatim; keep it short and actionable.

### Notes for the daemon agent

- JSON object key order is not significant; the client decodes by key.
- The client never sends partial lines and expects the same from the daemon:
  one complete JSON object per line, no embedded newlines, no pretty-printing.
- Replies must be small (< 4 KiB) and prompt; the client times out after 2s.
- The app never needs root and never touches utun, routes, or QUIC — every
  privileged effect flows through this socket.
