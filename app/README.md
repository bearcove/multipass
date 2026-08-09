# Multipass (menubar app)

SwiftUI menubar app for multipass — the seamless eth⇄wifi failover VPN.
macOS 27 only, SwiftPM executable, no sandbox, no root: the app is a thin UI
over the privileged `multipassd` LaunchDaemon, which owns the utun device and
the two noq QUIC connections.

```
swift build        # produces .build/debug/Multipass
```

## UI structure

| File | Role |
| --- | --- |
| `MultipassApp.swift` | `@main` App, single `MenuBarExtra` (`.window` style). Menubar icon is a state-reflecting SF Symbol: filled multipath glyph when connected, outline when disconnected, `network.slash` when the daemon is unreachable, animated arrows during a failover flash. |
| `MenuBarView.swift` | The panel: header with state, per-path rows (Wired / Wi-Fi, green = live / red = down, ACTIVE badge on the current path), failover banner, RTT / sent / received / up / down rates, prominent Connect/Disconnect toggle (`d` shortcut), Launch-at-Login toggle, Quit (`q`). |
| `TunnelController.swift` | `@Observable` model. Polls status once per second, serializes connect/disconnect commands, derives throughput rates from cumulative counters, and raises the failover flash when `active_path` changes while connected. |
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
| `{"cmd":"connect"}` | Bring the tunnel up (dial both underlays, configure utun). |
| `{"cmd":"disconnect"}` | Tear the tunnel down (remove routes, close connections). |
| `{"cmd":"benchmark_topology"}` | Query authoritative underlay paths, tunnel targets, and the reserved jax listener range. |

Unknown `cmd` values MUST be answered with a `type:"error"` reply.

### Responses (daemon → client)

**Status** — the only reply to `{"cmd":"status"}`:

```json
{"type":"status","connected":true,"wired":true,"wifi":true,"active_path":"wired","rtt_ms":12.4,"tx":123456,"rx":789012}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | `"status"` | Discriminator. |
| `connected` | bool | Tunnel is up (utun configured, at least one QUIC connection live). |
| `wired` | bool | Wired underlay path is currently live (its QUIC connection is up). |
| `wifi` | bool | Wi-Fi underlay path is currently live. |
| `active_path` | `"wired"` \| `"wifi"` \| null | The path currently winning seq dedup (delivering first copies). null when not connected. **The menubar failover flash triggers on changes to this field while `connected` stays true** — keep it stable per path and flip it only on a real delivery-path change, not per-packet jitter. |
| `rtt_ms` | number \| null | Smoothed RTT of the active path in milliseconds. null when unknown/disconnected. |
| `tx` | u64 | Cumulative tunnel payload bytes sent (into the tunnel) since the session started. MUST be monotonically non-decreasing across polls (the app derives rates from deltas); reset only on daemon restart / tunnel re-establishment. |
| `rx` | u64 | Cumulative tunnel payload bytes received. Same monotonicity rule. |

**Benchmark topology** — reply to `{"cmd":"benchmark_topology"}`:

```json
{"type":"benchmark_topology","protocol_version":2,"daemon_version":"<multipassd commit>","server_version":"<authenticated multipass-server commit or unknown while disconnected>","underlay_target":"10.10.10.1","tunnel_ipv4_target":"10.10.99.1","tunnel_ipv6_target":"fd00:99::1","listener_base_port":5210,"listener_count":16,"paths":[{"id":"wired","display_name":"Wired","interface":"en17","source_address":"10.10.10.171"},{"id":"wifi","display_name":"Wi-Fi","interface":"en0","source_address":"10.10.10.169"}]}
```

`paths` is ordered and uses stable IDs; benchmark code MUST treat it as an
array rather than fixed wired/Wi-Fi fields. `interface` and `source_address`
are the exact values resolved by the daemon. Either tunnel target may be null
when that family is unsupported. The half-open listener range is
`listener_base_port ..< listener_base_port + listener_count`; simultaneous
tests require at least one distinct listener per path. `protocol_version`
versions this control contract independently from the QUIC wire protocol.
`daemon_version` identifies the installed client daemon. `server_version`
identifies the currently authenticated server learned through the live QUIC
handshake and is `unknown` while disconnected.

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
