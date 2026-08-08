# Multipass Aggregation + IPv6 Design

**Date:** 2026-08-08
**Status:** Draft
**Goal:** ~3.3 Gbps combined throughput (2.4 Gbps wired + 900 Mbps wireless), seamless failover, global IPv6 connectivity.

## Context

Multipass currently replicates every IPv4 packet across both Ethernet and Wi-Fi paths. This provides seamless failover but caps throughput at the slower path (~900 Mbps) and doubles bandwidth usage. Scooter has no global IPv6 (only ULA); jax has no delegated prefix from the Freebox Pro despite requesting `/60`.

Two features are required:
1. **Aggregation:** Use both paths simultaneously for additive throughput
2. **IPv6:** Provide global IPv6 connectivity through the tunnel

Both changes require wire protocol modifications. They ship together under ALPN `multipass/1`.

## Aggregation Architecture

### Problem

QUIC DATAGRAM is unreliable and unordered. `send_datagram` with `drop=true` silently evicts queued datagrams under congestion (1 MiB default buffer). A successful call means "queued locally," not "delivered." Pure packet striping across paths loses packets when:
- A path dies between scheduling and delivery
- Congestion causes silent eviction
- The path's RTT spikes and packets arrive too late

The removed weighted scheduler demonstrated this: it striped packets but had no recovery mechanism, causing session loss during transitions.

### Solution: Loss-Recovered Striping

Each inner IP packet is retained by the sender until the receiver positively acknowledges it via selective ACK (SACK). On gap detection or path failure, the same sequence number is retransmitted on an alternate path. The receiver deduplicates by sequence number.

**Invariant:** A path failure cannot destroy the only copy of a packet. Ownership remains with the logical session until peer receipt is proven.

### Wire Protocol

```
Frame::Data { seq: u64, packet: Bytes }
    — Unchanged. Raw IP packet, any family.

Frame::Sack { largest_contiguous: u64, ranges: Vec<(u64, u64)> }
    — New. Cumulative ACK + selective ranges for out-of-order arrivals.
    — Sent on every ready path; deduplicated by receiver.

Frame::Assign {
    ipv4: Option<(Ipv4Addr, u8)>,      // client addr, prefix
    ipv6: Option<(Ipv6Addr, u8)>,      // client addr, prefix
    mtu: u16,                          // 1280
    dns: Vec<IpAddr>,                  // bounded, empty for v1
}
    — Extended from IPv4-only. Both families optional.
    — All paths must receive identical assignment for an epoch.
```

### Sender Behavior

1. **Retention:** Each `Data` frame is stored in a bounded ring (e.g., 4096 entries) keyed by `seq`.
2. **Scheduling:** A weighted scheduler assigns each new packet to the path with the lowest estimated delivery time:
   - `delivery_time = RTT/2 + queue_delay`
   - `queue_delay` estimated from `datagram_send_buffer_space` and recent send rate
   - Weights adjust continuously; no static 70/30 split
3. **Transmission:** Use `send_datagram_wait` (non-evicting). If the queue is full, the sender applies backpressure to the TUN reader rather than dropping.
4. **Retransmission:**
   - On SACK gap (missing sequence below `largest_contiguous`), retransmit on the other ready path
   - On path death, immediately retransmit all unacknowledged sequences assigned to that path
   - Retransmitted packets keep the same `seq`; receiver dedup absorbs them
5. **Retirement:** A packet is freed only when SACK confirms receipt. The ring must be large enough for `bandwidth × RTT × 2` (safety margin).

### Receiver Behavior

1. **Scoreboard:** Track received sequences in a sliding window (e.g., 4096 bits).
2. **Dedup:** First arrival of a `seq` is injected into TUN; duplicates are dropped.
3. **SACK Generation:**
   - `largest_contiguous`: highest sequence such that all sequences ≤ it are received
   - `ranges`: up to 8 selective ranges for out-of-order arrivals
   - Send SACK on every ready path (redundant, low cost)
   - Coalesce: send at most every 10ms or every 32 packets, whichever first

### Transition Safety

**Path joins:**
1. Dial, send Hello with client nonce
2. Receive Assign (same epoch)
3. Synchronize: server sends current SACK state; client sends current retention window bounds
4. Path becomes schedulable for new packets
5. Existing unacknowledged packets remain in the session; they may be retransmitted on any ready path

**Path dies:**
1. Reader task detects `read_datagram` error or QUIC close
2. All unacknowledged sequences assigned to the dead path are immediately retransmitted on surviving ready paths
3. Path is removed from scheduling until rejoin

**Path recovers:**
1. Re-dial, Hello/Assign as above
2. Brief shadow-copy window (e.g., 100ms): new packets are sent on both the recovered path and the primary path
3. Exit shadow mode when SACK confirms the recovered path is delivering

This preserves the proven replication behavior exactly where uncertainty is highest, without paying 2× cost continuously.

### Congestion Control Integration

Each QUIC connection has independent congestion control. The scheduler respects per-path limits:
- `path_stats(PathId::ZERO)` provides RTT, cwnd, lost packets
- `datagram_send_buffer_space()` provides queue occupancy
- A path with full queue or high loss is deprioritized
- The scheduler aims to keep both paths busy but not overflowing

### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Path blackhole | SACK gap, probe timeout | Retransmit on other path |
| Path congestion | `datagram_send_buffer_space` low | Scheduler shifts weight |
| Packet reordering | SACK ranges | None needed; dedup handles |
| Both paths die | All SACKs stop | Backpressure to TUN; session stalls until recovery |
| Receiver crash | Connection close | Client reconnects with new epoch |

### What This Does NOT Do

- **No FEC:** Forward error correction is optional future work for latency-sensitive traffic. SACK + retransmission is the correctness layer.
- **No reorder buffer:** Out-of-order delivery to the OS is acceptable. TCP handles reordering; UDP applications see it. A small buffer could be added later if needed.
- **No multipath TCP:** This is packet-level striping below TCP. MPTCP would require kernel support and per-flow state.

## IPv6 Architecture

### Problem

Scooter has no global IPv6. The Freebox Pro provides only SLAAC on the WAN `/64`; no prefix delegation despite DHCPv6-PD request. The current tunnel is IPv4-only:
- `Assign` carries only `Ipv4Addr`
- macOS utun drops `AF_INET6` frames
- Linux TUN has no IPv6 address or route
- MTU 1153 < IPv6 minimum 1280

### Solution: Dual-Stack with NAT66 (Now) / Native Routed (Future)

**Mode 1 — NAT66 (ships now):**
- ULA `/64` inside tunnel (e.g., `fd00:multipass::/64`)
- Jax assigns scooter `fd00:multipass::2`
- Jax SNATs ULA to its WAN global address (`2a05:6e02:1088:1c10::b1`)
- Outbound IPv6 works; inbound blocked by NAT
- No Freebox cooperation required

**Mode 2 — Native Routed (when PD arrives):**
- Freebox delegates `/60` to jax
- Jax assigns `/64` to tunnel (e.g., `2a05:6e02:1088:1c11::/64`)
- Scooter gets stable `::2` in that prefix
- No NAT; full end-to-end IPv6
- Requires Freebox ticket resolution

The `Assign` message carries which mode is active. Scooter configures accordingly. The mode is a jax-side configuration change; no client code changes needed to switch.

### MTU

- **Tunnel MTU: 1280** for both families
- IPv6 requires minimum 1280; this is standards-compliant
- QUIC DATAGRAM capacity must be ≥ 1289 bytes (1280 + 9 framing)
- Verify on each path after dial; a path below capacity is not dual-stack ready
- If underlay cannot carry 1289-byte DATAGRAMs, that path is IPv4-only (or tunnel segmentation is added later)

### macOS Changes

**utun.rs:**
- Accept both `AF_INET` and `AF_INET6` on read; return family with payload
- Derive family from IP version nibble on write; prepend correct AF tag
- Validate: version nibble 4 or 6, length ≤ MTU, header length sane

**routes.rs:**
- Configure `inet6` address on utun: `ifconfig utunN inet6 <addr> <peer> prefixlen <len>`
- Install IPv6 half-defaults: `route add -inet6 -net ::/1 -interface utunN` and `8000::/1`
- Pin IPv6 server endpoints: `route add -inet6 -host <server> -ifscope <iface> <iface-v6-addr>`
- Teardown reverses all

**main.rs:**
- Dual-stack canary: ICMPv6 Echo to server tunnel address, validate reply
- Atomic activation: both families configured before routes installed
- IPC: report `ipv4`, `ipv6`, `mtu` state separately

### Linux Changes

**tun.rs:**
- Use rtnetlink (not ioctl) to add IPv6 address: `ip -6 addr add <addr>/<prefix> dev tunX`
- Set MTU 1280, link up

**main.rs:**
- Bind `[::]:51823` for dual-stack QUIC (verify kernel accepts both families)
- Assign both families in `Assign` response
- nftables: forward `iifname tunX oifname WAN` for both families; masquerade IPv6 if NAT66 mode

### DNS

**v1: No DNS changes.** Scooter uses existing resolvers. Once IPv6 routes are up, AAAA queries flow through the tunnel. If the physical network's DNS becomes unreachable during a transition, resolution may fail even though the tunnel is alive. This is acceptable for v1; a tunnel-provided resolver can be added later.

### Inbound IPv6

**NAT66 mode:** Inbound connections to scooter's IPv6 address are blocked by NAT. This is acceptable for v1. Native routed mode could allow inbound if the Freebox firewall permits; not in scope.

## Production Verification Matrix

| Layer | Check |
|-------|-------|
| Wire | `multipass/1` negotiated; both paths receive identical Assign; old `multipass/0` rejected |
| QUIC | `max_datagram_size >= 1289` on each path after dial and reconnect |
| macOS | `ifconfig utunN` shows v4+v6, MTU 1280; outbound frames have correct AF tag |
| Routes | `route -n get` for v4 and v6 destinations selects utun; server pins use physical interfaces |
| Linux | `ip -d link show tunX` reports MTU 1280; `ip -6 addr` shows server address |
| Forwarding | `ping6` to public IPv6 works through tunnel; return path verified |
| ICMPv6 | Canary passes; Packet Too Big forwarded; no PMTU blackhole |
| Continuity | Long-lived TCP/UDP over v4 and v6 survives Ethernet pull/replug, Wi-Fi pull/replug |
| Aggregation | `iperf3` through tunnel achieves >1.5 Gbps combined (wired+wireless) |
| Failover | Unplug wired: throughput drops to ~900 Mbps, no session loss; replug: recovers to ~3.3 Gbps |
| SACK | Retransmission counter increments on forced path failure; no duplicate delivery to TUN |
| Status | IPC reports v4, v6, mtu, path readiness independently |

## Deployment Artifacts Needed

- Jax systemd unit for `multipass-server` (bind, restart, privileges)
- Jax sysctl: `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`
- Jax nftables fragment: TUN forward policy, IPv4 masquerade, IPv6 masquerade (NAT66 mode), ICMPv6 policy
- Address/prefix configuration: real ULA or delegated prefix, tunnel endpoints, DNS (future)
- Preflight check: refuse activation if IPv6 prefix not routed, forwarding off, nft rules absent, or DATAGRAM capacity insufficient

## Open Items

- Freebox Pro ticket for `/60` delegation (drafted, awaiting submission)
- Native routed mode activation when delegation arrives
- DNS resolver configuration (v2)
- Inbound IPv6 firewall policy (v2, native mode only)
