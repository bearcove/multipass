# multipass — architecture contract

Seamless eth<->wifi failover VPN for Amos's desk. macOS 27+ client, Linux
(router) server. All our own Rust + SwiftUI. Transport already proven.

## The proven core

Two independent noq QUIC connections, one per interface (wired en17 / wifi
en0). Every packet carries a sequence number; the receiver dedups by it. The
measured baseline (step 0) sent every packet on BOTH connections (active-active
redundancy) and survived unplug/replug with 0.1% loss, 184ms worst gap. That
proves the failover property.

## Send policy: active-active replication

The send path transmits every raw IP packet on every authenticated live path
with the same sequence number. The receiver accepts the first arrival and
deduplicates later copies. This costs roughly 2x uplink bandwidth while both
paths are healthy, but removes the detection window that made scheduler-based
striping lose packets during a physical link transition.

True bandwidth aggregation is not implemented. If added later, it needs an
explicit transition policy that preserves the already-proven zero-session-loss
contract rather than silently replacing replication.

## Why datagrams, not streams (decided)

noq offers both. Streams (open_bi) are reliable+ordered per stream but would
require terminating TCP inside the tunnel (a proxy, not a VPN) and break
UDP/ICMP. We carry RAW IP PACKETS, one per QUIC datagram, on the unreliable
datagram lane with seq-dedup. Inner TCP retransmits on its own; inner UDP/ICMP
just work. Same model as mqvpn's datagram lane.

## Components

### multipass-proto (Rust lib)
Shared wire format + logic, no I/O. Depends only on `bytes`.
- `Frame` enum: the datagram payload. Serialized manually (no serde).
  - `Data { seq: u64, packet: Bytes }` — one IPv4 packet from the TUN.
  - `Control(ControlMsg)` — see below.
- `ControlMsg`: `Hello { client_nonce }`, `Assign { addr: Ipv4Addr, prefix: u8,
  mtu: u16 }`, `Ping`, `Pong`. (Address assignment + liveness.)
- `Dedup`: a fixed-size sliding-window dedup set keyed by seq (ring buffer,
  window 4096). `insert(seq) -> bool` (true = first time).
- No allocation on the hot path beyond the packet Bytes itself.

### multipassd (Rust bin, root LaunchDaemon on scooter)
Owns the tunnel. Privileged.
- Creates a `utun` device via the `utun` syscall control (PF_SYSTEM/
  SYSPROTO_CONTROL, UTUN_CONTROL_NAME) — the only way on macOS; no
  NetworkExtension (that needs an app extension + entitlements; we want a
  plain daemon).
- Assigns the tunnel IP from `Assign`, sets MTU, adds routes (full-tunnel:
  default route via utun, plus host routes pinning the server's underlay IPs
  to their physical interfaces so the tunnel's own QUIC packets never recurse
  into the tunnel).
- Reads IP packets from utun -> wraps in Frame::Data -> send on BOTH conns.
- read_datagram on both conns -> dedup -> write packet to utun.
- Manages the two noq connections: bind each to its interface source IP,
  reconnect on path loss / network change, re-dial on interface up/down
  (SCNetworkReachability / route-monitor).
- XPC-ish IPC: a Unix domain socket at /var/run/multipassd.sock, newline-JSON,
  for the menubar app to query status and toggle the tunnel. (Unix socket, NOT
  real NSXPC — simpler from Rust; app side uses a tiny POSIX client.)

### multipass-server (Rust bin on router)
- noq server, accepts the two client connections (same ALPN).
- Creates a `tun` device (/dev/net/tun), owns subnet 10.10.99.0/24 (server is
  .1). Assigns the client .2 via ControlMsg::Assign.
- Decapsulate inbound frames -> write raw packet to tun. router's existing
  nftables masquerade (10.10.0.0/16 -> WAN) handles egress; ip_forward=1
  already set. NO new firewall/NAT rules needed for the base case.
- Outbound: read tun -> wrap -> send on the client's currently-live conn(s).

### multipass-app (SwiftUI, macOS 27)
Menubar app (LSUIElement), SMAppService launch-at-login like baratheon.
- Shows per-path status (wired/wifi live? rtt?), a failover flash when the
  active path changes, bytes up/down.
- Toggle connect/disconnect; it commands multipassd over the unix socket.
- Bundles multipassd and installs/loads the LaunchDaemon (SMAppService.daemon)
  — the ONLY step that needs the user's password, clearly explained.

## Wire/ALPN
ALPN = "multipass/0". Server port 51823/udp (51822 was mqvpn, now removed).
Tunnel subnet 10.10.99.0/24 (server .1, client .2). Reuses router's existing
masquerade; no firewall delta for the base case.

## Non-goals (v1)
- No IPv6 inside the tunnel (scooter has no global v6 anyway).
- No aggregation/bonding for throughput — active-active is for REDUNDANCY.
  (Both conns carry every packet = 2x bandwidth cost; acceptable on a desk LAN.)
- No multi-client (one client: scooter). Server handles one session.
- No Windows/Linux client.
