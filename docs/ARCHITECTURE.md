# multipass — architecture contract

Seamless eth<->wifi failover VPN for Amos's desk. macOS 27+ client, Linux
(router) server. All our own Rust + SwiftUI. Transport already proven.

## The proven core

Two independent noq QUIC connections, one per interface (wired en17 / wifi
en0). Every packet carries a sequence number; the receiver dedups by it. The
measured baseline (step 0) sent every packet on BOTH connections (active-active
redundancy) and survived unplug/replug with 0.1% loss, 184ms worst gap. That
proves the failover property.

## Send policy: loss-recovered aggregation (striping)

The send path **stripes** each raw IP packet onto ONE path chosen by a
congestion-aware scheduler (lowest estimated delivery time: path RTT plus a
queue-occupancy penalty). This combines both links' bandwidth — a single flow
can reach ~2.4 Gbps wired + ~0.9 Gbps Wi-Fi ≈ 3.3 Gbps.

Striping alone loses packets when a path dies between scheduling and delivery,
so aggregation is layered on a reliability contract:

- Every packet is retained in a bounded `SendWindow` until the peer's
  selective ACK (`Frame::Sack`) confirms receipt.
- The receiver tracks arrivals in a `SackScoreboard` and broadcasts SACKs
  (largest-contiguous + up to 8 out-of-order ranges) on all ready paths.
- On a SACK gap, path death, or path recovery, the same sequence is
  retransmitted on a surviving path. The receiver's `Dedup` absorbs the
  retransmission, so the tunnel never sees a duplicate.
- A path failure therefore cannot destroy the only copy of a packet: ownership
  stays with the logical session until receipt is proven. This is the
  invariant the earlier naive scheduler violated.

Both directions aggregate symmetrically (client→server in `Transport`,
server→client in `Session`). IPv6 is dual-stack: `Assign` carries optional v4
and v6 tunnel addresses, MTU 1280, and the macOS/Linux TUN layers are
family-aware.

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
  - `Data { seq, packet }` — one raw IP packet (v4 or v6) from the TUN.
  - `Hello { client_nonce }`, `Ping`, `Pong` — handshake + liveness.
  - `Assign { ipv4, ipv6, mtu, dns }` — dual-stack address assignment.
  - `Sack { largest_contiguous, ranges }` — selective ACK for aggregation.
- `Dedup`: fixed-size sliding-window dedup set keyed by seq (ring buffer,
  window 4096). `insert(seq) -> bool` (true = first time).
- `SackScoreboard`: receive-side window that generates SACKs.
- `SendWindow`: send-side retention ring; retransmits on SACK gap/path death.
- `Scheduler`: congestion-aware path picker (RTT + queue-occupancy cost).
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
- Reads IP packets from utun -> wraps in Frame::Data -> stripe onto the
  scheduler-chosen conn (retained in SendWindow for SACK retransmit).
- read_datagram on both conns -> dedup -> write packet to utun (family-aware
  AF_INET/AF_INET6 framing). Consumes inbound SACKs to drive the send window;
  broadcasts SACKs for the reverse direction.
- Manages the two noq connections: bind each to its interface source IP,
  reconnect on path loss / network change, re-dial on interface up/down
  (SCNetworkReachability / route-monitor).
- XPC-ish IPC: a Unix domain socket at /var/run/multipassd.sock, newline-JSON,
  for the menubar app to query status and toggle the tunnel. (Unix socket, NOT
  real NSXPC — simpler from Rust; app side uses a tiny POSIX client.)

### multipass-server (Rust bin on router)
- noq server, accepts the two client connections (same ALPN), treats them as
  one logical session keyed by client epoch.
- Creates a `tun` device (/dev/net/tun), owns 10.10.99.1/24 + fd00:99::1/64.
  Assigns the client .2 / ::2 via Frame::Assign.
- Inbound: decapsulate frames -> SackScoreboard + dedup -> write to TUN;
  broadcasts SACKs every 10ms so the client can retire/retransmit.
- Outbound: read tun -> stripe onto the scheduler-chosen client conn
  (SendWindow retention + SACK retransmit, symmetric with the client).
- IPv4 egress: existing nftables masquerade (10.10.0.0/16 -> WAN). IPv6
  egress: NAT66 (deploy/multipass-nat66.nft).

### multipass-app (SwiftUI, macOS 27)
Menubar app (LSUIElement), SMAppService launch-at-login like baratheon.
- Shows per-path status (wired/wifi live? rtt?), a failover flash when the
  active path changes, bytes up/down.
- Toggle connect/disconnect; it commands multipassd over the unix socket.
- Bundles multipassd and installs/loads the LaunchDaemon (SMAppService.daemon)
  — the ONLY step that needs the user's password, clearly explained.

## Wire/ALPN
ALPN = "multipass/1". Server port 51823/udp (51822 was mqvpn, now removed).
Tunnel subnet 10.10.99.0/24 (server .1, client .2) plus ULA fd00:99::/64
(server ::1, client ::2), MTU 1280. IPv4 reuses the router's existing
masquerade; IPv6 uses NAT66 (deploy/multipass-nat66.nft) until the Freebox
prefix delegation arrives, then switches to native routed.

## Non-goals (v1)
- No multi-client (one client: scooter). Server handles one session.
- No Windows/Linux client.
- No DNS configuration through the tunnel (uses existing resolvers).
- No inbound IPv6 (NAT66 blocks it; native routed mode may add it later).
