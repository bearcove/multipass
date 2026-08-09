# multipass

Experimental dual-link packet tunnel for a Mac connected over Ethernet and
Wi-Fi at the same time. The target is to aggregate both links for throughput
while preserving ordinary TCP, UDP, ICMP, IPv4, and IPv6 sessions when either
physical path disappears.

The macOS 27+ client and Linux router server work end to end today, including
dual-stack forwarding. Seamless failover and full aggregate throughput are not
yet proven; see [Status](#status) for measured results and the current blocker.

## Why this exists

At the desk, the MacBook is on **wired Ethernet and Wi-Fi at the same time**.
The moment you unplug the cable, every TCP/UDP session bound to the wired
interface's address dies. We wanted unplugging to be a non-event.

The off-the-shelf answer is **[mqvpn](https://github.com/mp0rta/mqvpn)** — a
multipath QUIC VPN that does exactly this. It's a fine piece of work and it
proved the concept for us. But it's a ~28k-line C binary that runs as **root**
and owns your routing table, and we weren't willing to hand it the keys
without a security review we didn't have the appetite for. So:

> **multipass is a loving reimplementation of just the part of mqvpn we care
> about, in Rust, on a stack we already trust (noq / QUIC).** Full respect to
> mp0rta — mqvpn showed the idea works and is far more feature-complete
> (Windows/Linux/Android, bandwidth aggregation, FEC, hybrid TCP lane, a real
> control API). If you want the mature, multiplatform thing, use mqvpn.
> multipass is the small, hackable, ours version.

We also tried plain **WireGuard + MPTCP** first. It can't do this on macOS:
MPTCP is per-app opt-in via Network.framework (your SSH client and browser
don't), and WireGuard roaming still stalls sessions for seconds on a path
drop. The seamless property needs multipath at the *packet* layer, not the
transport layer — which is the whole trick.

## Current scope

- One macOS client (`scooter`) and one Linux router/server (`jax`).
- Two simultaneously active underlay paths: wired Ethernet and Wi-Fi.
- Raw IPv4 and IPv6 packets through one stable dual-stack tunnel interface.
- Bidirectional bandwidth aggregation: client→server and server→client.
- Sequence-numbered packets, selective acknowledgements, retransmission, and
  receive-side deduplication.
- IPv4 masquerading and IPv6 NAT66 at the router. Native routed IPv6 can replace
  NAT66 once ISP prefix delegation is available.

Multi-client operation and non-macOS clients are outside the current scope.

## How it works

- The client opens **two independent QUIC connections** to the router: one
  bound to the wired interface and one bound to Wi-Fi.
- A congestion-aware scheduler sends each tunnel packet on one path according
  to measured RTT and outgoing queue pressure. The intended result is striping
  traffic across both links rather than duplicating every packet.
- Every packet carries a **sequence number** and remains in a bounded send
  window until the peer's **selective ACK** confirms receipt. Missing sequences
  can be retransmitted on a surviving path; the receiver deduplicates by
  sequence number.
- The tunnel carries both IPv4 and IPv6 at MTU 1280. Applications continue to
  use ordinary sockets and see only the stable tunnel addresses.

```
   your apps (ssh, browser, git — anything)
        │  IPv4 + IPv6, unchanged
        ▼
   ┌─────────────┐      ┌── QUIC A (en17, wired) ──┐
   │  utun dev   │─────►│  scheduler + send window  │──► router ──► internet
   │ dual-stack  │      └── QUIC B (en0, Wi-Fi)  ──┘
   └─────────────┘       sequence + SACK + dedup
       stable tunnel addresses across physical paths
```

## Status

**Experimental. The dual-stack tunnel works; the seamless-failover contract
does not yet. Do not rely on the current build to preserve sessions during a
path failure.**

Verified on the real `scooter` ↔ `jax` deployment:

- Both wired and Wi-Fi QUIC connections authenticate concurrently.
- IPv4 tunnel reachability: 5/5 pings, 0% loss, 1.30 ms average.
- IPv6 tunnel reachability: 5/5 pings, 0% loss, 3.28 ms average.
- Public IPv6 through NAT66: 5/5 pings, 0% loss, 1.31 ms average.
- IPv4 and IPv6 HTTPS both complete through the tunnel.
- The router has `10.10.99.1/24` and `fd00:99::1/64`; the client has
  `10.10.99.2/24` and `fd00:99::2/64`.

Current throughput measurements (`iperf3`, four streams):

| Path | Throughput |
| --- | ---: |
| Raw wired | 2.35 Gbit/s |
| Raw Wi-Fi | 0.68 Gbit/s |
| Raw combined capacity | 3.03 Gbit/s |
| Tunnel upload | 0.66 Gbit/s |
| Tunnel download | 1.38 Gbit/s |

Aggregation machinery exists in both directions, but the tunnel is not yet
reaching the sum of the physical links.

The critical correctness defect is silent path loss. In a production test that
blackholed only wired QUIC traffic for eight seconds, concurrent IPv4 and IPv6
tunnel pings each delivered 173/250 packets: **30.8% loss**, covering nearly the
entire blackhole interval. The failed connection remained locally "alive", so
the scheduler continued choosing it instead of moving traffic to Wi-Fi. Path
death consumption, bounded liveness detection, non-blocking redial, and the
resulting retransmission path must be fixed and re-verified before the project
can claim seamless failover.

See `docs/ARCHITECTURE.md` for the protocol and component design.

## Layout

- `crates/multipass` — the client daemon (`multipassd`): utun + dual-connection
  transport + routing, runs as root on the Mac.
- `crates/multipass-proto` — the wire format (framing, dedup, control
  messages). Shared by client and server, no I/O.
- `crates/multipass-server` — the server (router): decapsulate, forward, NAT.
- `app/` — the SwiftUI menubar app (macOS 27).

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache 2.0](LICENSE-APACHE), at your option.
