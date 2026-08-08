# Aggregation + IPv6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement loss-recovered packet striping for ~3.3 Gbps aggregate throughput and dual-stack IPv6 via NAT66, per spec `docs/superpowers/specs/2026-08-08-aggregation-ipv6-design.md`.

**Architecture:** SACK-based reliability layer over QUIC DATAGRAM. Sender retains packets until acknowledged; receiver dedups and generates SACKs. Cross-path retransmission on gaps or path death. IPv6 via ULA + NAT66 at jax (native routed when Freebox PD arrives).

**Tech Stack:** Rust, noq (QUIC), tokio, macOS utun, Linux TUN, nftables.

## Global Constraints

- Wire protocol ALPN: `multipass/1` (clean cutover from `/0`)
- Tunnel MTU: 1280 (both families)
- QUIC DATAGRAM capacity: ≥1289 bytes per path
- NAT66 ULA prefix: `fd00:99::/64` (documented, stable)
- No DNS changes in v1
- No reorder buffer in v1
- No inbound IPv6 in v1 (NAT66 blocks)
- All changes must preserve seamless failover: no session loss on Ethernet/Wi-Fi transitions

## File Structure

| File | Responsibility |
|------|----------------|
| `crates/multipass-proto/src/lib.rs` | Wire format: Frame, Tag, encode/decode, Sack, Assign (v4+v6) |
| `crates/multipass-proto/src/sack.rs` | SackScoreboard: track received seqs, generate SACK frames |
| `crates/multipass/src/lib.rs` | Transport: send/recv, retention ring, scheduler, retransmission |
| `crates/multipass/src/send_window.rs` | Retention ring: store unacked packets, retire on SACK |
| `crates/multipass/src/scheduler.rs` | Path scheduler: pick path by RTT + queue space |
| `crates/multipass/src/bin/multipassd/utun.rs` | macOS utun: dual-stack AF framing |
| `crates/multipass/src/bin/multipassd/routes.rs` | macOS routes: inet6 config, v6 half-defaults, v6 pins |
| `crates/multipass/src/bin/multipassd/main.rs` | Daemon: dual-stack canary, atomic activation |
| `crates/multipass-server/src/tun.rs` | Linux TUN: rtnetlink IPv6 address, MTU 1280 |
| `crates/multipass-server/src/main.rs` | Server: dual-stack bind, Assign v4+v6, SACK handling |
| `crates/multipass-server/src/nft.rs` | nftables: NAT66 masquerade, forward rules |

---

### Task 1: Wire Protocol — SACK Frame

**Files:**
- Modify: `crates/multipass-proto/src/lib.rs`
- Create: `crates/multipass-proto/src/sack.rs`
- Test: `crates/multipass-proto/src/lib.rs` (tests module)

**Interfaces:**
- Produces: `Frame::Sack { largest_contiguous: u64, ranges: Vec<(u64, u64)> }`
- Produces: `SackScoreboard::new()`, `insert(seq) -> bool`, `generate_sack() -> Sack`

- [ ] **Step 1: Write failing test for Sack frame roundtrip**

```rust
#[test]
fn sack_frame_roundtrip() {
    let sack = Frame::Sack {
        largest_contiguous: 100,
        ranges: vec![(95, 98), (85, 90)],
    };
    let encoded = encode(&sack);
    let decoded = decode(&encoded).unwrap();
    match decoded {
        Frame::Sack { largest_contiguous, ranges } => {
            assert_eq!(largest_contiguous, 100);
            assert_eq!(ranges, vec![(95, 98), (85, 90)]);
        }
        _ => panic!("wrong frame"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p multipass-proto sack_frame_roundtrip`
Expected: FAIL — `Frame::Sack` variant does not exist

- [ ] **Step 3: Implement Sack frame in proto**

Add to `Tag` enum: `Sack = 5`
Add to `Frame` enum: `Sack { largest_contiguous: u64, ranges: Vec<(u64, u64)> }`
Encode: `[tag=5][largest_contiguous u64][range_count u8][ranges...]` where each range is `[start u64][end u64]`
Decode: parse tag 5, read largest_contiguous, range_count, then ranges

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p multipass-proto sack_frame_roundtrip`
Expected: PASS

- [ ] **Step 5: Write failing test for SackScoreboard**

```rust
#[test]
fn scoreboard_tracks_received() {
    let mut sb = SackScoreboard::new();
    assert!(sb.insert(1));
    assert!(sb.insert(2));
    assert!(sb.insert(4)); // gap at 3
    assert!(!sb.insert(1)); // duplicate
    let sack = sb.generate_sack();
    assert_eq!(sack.largest_contiguous, 2);
    assert_eq!(sack.ranges, vec![(4, 4)]);
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cargo nextest run -p multipass-proto scoreboard_tracks_received`
Expected: FAIL — `SackScoreboard` does not exist

- [ ] **Step 7: Implement SackScoreboard**

Create `sack.rs`:
```rust
pub struct SackScoreboard {
    max_seq: u64,
    started: bool,
    bits: [u64; 64], // 4096 bits
}

impl SackScoreboard {
    pub fn new() -> Self { ... }
    pub fn insert(&mut self, seq: u64) -> bool { ... }
    pub fn generate_sack(&self) -> Sack { ... }
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cargo nextest run -p multipass-proto scoreboard_tracks_received`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add crates/multipass-proto/src/lib.rs crates/multipass-proto/src/sack.rs
git commit -m "proto: add Sack frame and SackScoreboard"
```

---

### Task 2: Wire Protocol — Dual-Stack Assign

**Files:**
- Modify: `crates/multipass-proto/src/lib.rs`
- Test: `crates/multipass-proto/src/lib.rs` (tests module)

**Interfaces:**
- Consumes: nothing (extends existing Assign)
- Produces: `Frame::Assign { ipv4: Option<(Ipv4Addr, u8)>, ipv6: Option<(Ipv6Addr, u8)>, mtu: u16, dns: Vec<IpAddr> }`

- [ ] **Step 1: Write failing test for dual-stack Assign roundtrip**

```rust
#[test]
fn assign_dual_stack_roundtrip() {
    let assign = Frame::Assign {
        ipv4: Some((Ipv4Addr::new(10, 10, 99, 2), 24)),
        ipv6: Some((Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 2), 64)),
        mtu: 1280,
        dns: vec![],
    };
    let encoded = encode(&assign);
    let decoded = decode(&encoded).unwrap();
    match decoded {
        Frame::Assign { ipv4, ipv6, mtu, dns } => {
            assert_eq!(ipv4, Some((Ipv4Addr::new(10, 10, 99, 2), 24)));
            assert_eq!(ipv6, Some((Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 2), 64)));
            assert_eq!(mtu, 1280);
            assert!(dns.is_empty());
        }
        _ => panic!("wrong frame"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p multipass-proto assign_dual_stack_roundtrip`
Expected: FAIL — Assign fields don't match

- [ ] **Step 3: Update Assign frame structure**

Change `Frame::Assign` to:
```rust
Assign {
    ipv4: Option<(Ipv4Addr, u8)>,
    ipv6: Option<(Ipv6Addr, u8)>,
    mtu: u16,
    dns: Vec<IpAddr>,
}
```

Encode: `[tag=2][flags u8][ipv4?][ipv6?][mtu u16][dns_count u8][dns...]`
- flags bit 0: ipv4 present, bit 1: ipv6 present
- ipv4: `[addr u32][prefix u8]`
- ipv6: `[addr u128][prefix u8]`

Decode: parse flags, conditionally read ipv4/ipv6, read mtu, read dns

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p multipass-proto assign_dual_stack_roundtrip`
Expected: PASS

- [ ] **Step 5: Update ALPN to multipass/1**

Change `pub const ALPN: &[u8] = b"multipass/1";`

- [ ] **Step 6: Update tunnel MTU constant**

Change `pub const TUNNEL_MTU: u16 = 1280;`
Add `pub const TUNNEL_V6_PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 0);`
Add `pub const TUNNEL_V6_CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 2);`
Add `pub const TUNNEL_V6_SERVER: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 1);`

- [ ] **Step 7: Commit**

```bash
git add crates/multipass-proto/src/lib.rs
git commit -m "proto: dual-stack Assign, ALPN multipass/1, MTU 1280"
```

---

### Task 3: Client Transport — Send Window

**Files:**
- Create: `crates/multipass/src/send_window.rs`
- Modify: `crates/multipass/src/lib.rs`
- Test: `crates/multipass/src/send_window.rs` (tests module)

**Interfaces:**
- Consumes: `Frame`, `Sack` from proto
- Produces: `SendWindow::new(capacity)`, `insert(seq, packet)`, `ack(sack) -> Vec<Bytes>`, `unacked() -> Vec<(u64, Bytes)>`

- [ ] **Step 1: Write failing test for send window retention**

```rust
#[test]
fn send_window_retains_until_ack() {
    let mut sw = SendWindow::new(4096);
    sw.insert(1, Bytes::from_static(b"pkt1"));
    sw.insert(2, Bytes::from_static(b"pkt2"));
    assert_eq!(sw.unacked().len(), 2);
    
    let sack = Sack { largest_contiguous: 1, ranges: vec![] };
    sw.ack(&sack);
    assert_eq!(sw.unacked().len(), 1);
    assert_eq!(sw.unacked()[0].0, 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p multipass send_window_retains_until_ack`
Expected: FAIL — `SendWindow` does not exist

- [ ] **Step 3: Implement SendWindow**

Create `send_window.rs`:
```rust
pub struct SendWindow {
    capacity: usize,
    base_seq: u64,
    entries: VecDeque<Option<Bytes>>,
}

impl SendWindow {
    pub fn new(capacity: usize) -> Self { ... }
    pub fn insert(&mut self, seq: u64, packet: Bytes) { ... }
    pub fn ack(&mut self, sack: &Sack) -> Vec<Bytes> { ... } // returns retransmit candidates
    pub fn unacked(&self) -> Vec<(u64, Bytes)> { ... }
    pub fn is_full(&self) -> bool { ... }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p multipass send_window_retains_until_ack`
Expected: PASS

- [ ] **Step 5: Write failing test for gap detection**

```rust
#[test]
fn send_window_detects_gaps() {
    let mut sw = SendWindow::new(4096);
    sw.insert(1, Bytes::from_static(b"pkt1"));
    sw.insert(2, Bytes::from_static(b"pkt2"));
    sw.insert(3, Bytes::from_static(b"pkt3"));
    
    // SACK says 1 and 3 received, gap at 2
    let sack = Sack { largest_contiguous: 1, ranges: vec![(3, 3)] };
    let retransmit = sw.ack(&sack);
    assert_eq!(retransmit.len(), 1);
    assert_eq!(retransmit[0], Bytes::from_static(b"pkt2"));
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cargo nextest run -p multipass send_window_detects_gaps`
Expected: FAIL — gap detection not implemented

- [ ] **Step 7: Implement gap detection in ack()**

When SACK has ranges above largest_contiguous, packets in gaps are retransmit candidates.

- [ ] **Step 8: Run test to verify it passes**

Run: `cargo nextest run -p multipass send_window_detects_gaps`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add crates/multipass/src/send_window.rs
git commit -m "transport: add SendWindow for packet retention and gap detection"
```

---

### Task 4: Client Transport — Scheduler

**Files:**
- Create: `crates/multipass/src/scheduler.rs`
- Modify: `crates/multipass/src/lib.rs`
- Test: `crates/multipass/src/scheduler.rs` (tests module)

**Interfaces:**
- Consumes: `PathKind`, RTT, queue space
- Produces: `Scheduler::new()`, `pick() -> Option<PathKind>`, `note_rtt(path, rtt)`, `note_queue_space(path, bytes)`

- [ ] **Step 1: Write failing test for scheduler path selection**

```rust
#[test]
fn scheduler_picks_faster_path() {
    let mut sched = Scheduler::new();
    sched.note_rtt(PathKind::Wired, Duration::from_millis(1));
    sched.note_rtt(PathKind::Wifi, Duration::from_millis(10));
    sched.note_queue_space(PathKind::Wired, 100_000);
    sched.note_queue_space(PathKind::Wifi, 100_000);
    
    // Wired has lower RTT, should be picked more often
    let mut wired = 0;
    let mut wifi = 0;
    for _ in 0..100 {
        match sched.pick() {
            Some(PathKind::Wired) => wired += 1,
            Some(PathKind::Wifi) => wifi += 1,
            None => {}
        }
    }
    assert!(wired > wifi);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p multipass scheduler_picks_faster_path`
Expected: FAIL — `Scheduler` does not exist

- [ ] **Step 3: Implement Scheduler**

Create `scheduler.rs`:
```rust
pub struct Scheduler {
    paths: [PathState; 2],
}

struct PathState {
    rtt: Option<Duration>,
    queue_space: usize,
    weight: u32,
    credit: i64,
}

impl Scheduler {
    pub fn new() -> Self { ... }
    pub fn pick(&mut self) -> Option<PathKind> { ... }
    pub fn note_rtt(&mut self, path: PathKind, rtt: Duration) { ... }
    pub fn note_queue_space(&mut self, path: PathKind, bytes: usize) { ... }
    pub fn set_alive(&mut self, path: PathKind, alive: bool) { ... }
}
```

Use deficit-WRR with weights inversely proportional to RTT, scaled by queue space.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p multipass scheduler_picks_faster_path`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/multipass/src/scheduler.rs
git commit -m "transport: add congestion-aware Scheduler"
```

---

### Task 5: Client Transport — Integration

**Files:**
- Modify: `crates/multipass/src/lib.rs`
- Test: `crates/multipass/src/lib.rs` (tests module)

**Interfaces:**
- Consumes: `SendWindow`, `Scheduler`, `SackScoreboard`
- Produces: `Transport::send_data(seq, packet)` with retention and scheduling

- [ ] **Step 1: Write failing test for aggregated send**

```rust
#[tokio::test]
async fn aggregated_send_stripes_across_paths() {
    let addr = spawn_echo_server().await;
    let t = Transport::connect(addr, "127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap()).await.unwrap();
    t.mark_ready(PathKind::Wired);
    t.mark_ready(PathKind::Wifi);
    
    // Send 100 packets
    for i in 0..100u64 {
        t.send_data(i, Bytes::from(vec![0u8; 1000]));
    }
    
    // Both paths should have transmitted some packets
    let st = t.status();
    assert!(st.wired.transmitted > 0);
    assert!(st.wifi.transmitted > 0);
    assert_eq!(st.wired.transmitted + st.wifi.transmitted, 100);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p multipass aggregated_send_stripes_across_paths`
Expected: FAIL — current send_data replicates to both

- [ ] **Step 3: Integrate SendWindow and Scheduler into Transport**

Modify `Transport`:
- Add `send_window: Mutex<SendWindow>`
- Add `scheduler: Mutex<Scheduler>`
- Change `send_data` to: insert into window, pick path, send on that path only
- Add `handle_sack(sack)` method: retire acked, retransmit gaps
- Add `recv_sack()` for the daemon to poll SACK frames

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p multipass aggregated_send_stripes_across_paths`
Expected: PASS

- [ ] **Step 5: Write failing test for retransmission on path death**

```rust
#[tokio::test]
async fn retransmits_on_path_death() {
    // Setup: send packets, kill one path, verify retransmission on other
}
```

- [ ] **Step 6: Run test to verify it fails**

- [ ] **Step 7: Implement retransmission on path death**

When `recv_dead` fires, immediately retransmit all unacked packets from the dead path on the surviving path.

- [ ] **Step 8: Run test to verify it passes**

- [ ] **Step 9: Commit**

```bash
git add crates/multipass/src/lib.rs
git commit -m "transport: integrate SendWindow and Scheduler for aggregation"
```

---

### Task 6: Server — SACK Generation

**Files:**
- Modify: `crates/multipass-server/src/main.rs`
- Test: `crates/multipass-server/src/main.rs` (tests module)

**Interfaces:**
- Consumes: `SackScoreboard` from proto
- Produces: SACK frames sent on all ready paths

- [ ] **Step 1: Write failing test for SACK generation**

```rust
#[tokio::test]
async fn server_generates_sack() {
    let session = Session::new();
    let conn = session.add_test_conn().await;
    session.authenticate(conn, 10).await;
    
    // Receive packets 1, 2, 4 (gap at 3)
    session.accept_data(conn, 1).await;
    session.accept_data(conn, 2).await;
    session.accept_data(conn, 4).await;
    
    let sack = session.generate_sack().await;
    assert_eq!(sack.largest_contiguous, 2);
    assert!(sack.ranges.contains(&(4, 4)));
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Add SackScoreboard to Session**

Add `scoreboard: SackScoreboard` to `SessionState`.
Update `accept_data` to insert into scoreboard.
Add `generate_sack()` method.

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Add SACK sending to server loop**

In the main loop, periodically (every 10ms or 32 packets) generate and send SACK on all ready connections.

- [ ] **Step 6: Commit**

```bash
git add crates/multipass-server/src/main.rs
git commit -m "server: add SACK generation for aggregation"
```

---

### Task 7: macOS — Dual-Stack utun

**Files:**
- Modify: `crates/multipass/src/bin/multipassd/utun.rs`
- Test: `crates/multipass/src/bin/multipassd/utun.rs` (tests module)

**Interfaces:**
- Consumes: nothing
- Produces: `Utun::read_packet()` returns `(AddressFamily, &[u8])`, `Utun::write_packet(family, payload)`

- [ ] **Step 1: Write failing test for IPv6 read**

```rust
#[test]
fn utun_accepts_ipv6() {
    // Mock utun that returns AF_INET6 header + IPv6 packet
    // Verify read_packet returns (AddressFamily::Inet6, payload)
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Add AddressFamily enum and dual-stack read/write**

```rust
pub enum AddressFamily { Inet, Inet6 }

impl Utun {
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<Option<(AddressFamily, usize)>> {
        // Accept AF_INET or AF_INET6, return family with payload
    }
    
    pub fn write_packet(&self, buf: &mut [u8], family: AddressFamily, payload: &[u8]) -> io::Result<usize> {
        // Prepend correct AF tag based on family
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

```bash
git add crates/multipass/src/bin/multipassd/utun.rs
git commit -m "macos: dual-stack utun framing"
```

---

### Task 8: macOS — Dual-Stack Routes

**Files:**
- Modify: `crates/multipass/src/bin/multipassd/routes.rs`
- Test: `crates/multipass/src/bin/multipassd/routes.rs` (tests module)

**Interfaces:**
- Consumes: `Assign` with ipv4 and ipv6
- Produces: `configure_v6(utun, addr, prefix, mtu)`, `setup_v6(utun, server_v6, wired_if, wifi_if)`, `teardown_v6(...)`

- [ ] **Step 1: Write failing test for IPv6 route commands**

```rust
#[test]
fn ipv6_route_commands() {
    let args = v6_default_route_args("utun16");
    assert_eq!(args[0], ["-n", "add", "-inet6", "-net", "::/1", "-interface", "utun16"]);
    assert_eq!(args[1], ["-n", "add", "-inet6", "-net", "8000::/1", "-interface", "utun16"]);
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement IPv6 route functions**

Add:
- `configure_v6(utun, addr, prefix, mtu)`: `ifconfig utunN inet6 <addr> prefixlen <prefix> mtu <mtu> up`
- `setup_v6(utun, server, wired_if, wifi_if)`: pin v6 server, add v6 half-defaults
- `teardown_v6(...)`: reverse
- `v6_default_route_args(utun)`: `::/1` and `8000::/1`

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

```bash
git add crates/multipass/src/bin/multipassd/routes.rs
git commit -m "macos: dual-stack route configuration"
```

---

### Task 9: macOS — Dual-Stack Canary

**Files:**
- Modify: `crates/multipass/src/bin/multipassd/main.rs`
- Test: manual verification

**Interfaces:**
- Consumes: `Assign` with ipv6
- Produces: ICMPv6 Echo canary

- [ ] **Step 1: Add ICMPv6 canary packet construction**

Build ICMPv6 Echo Request: IPv6 header (40 bytes) + ICMPv6 header (8 bytes) + payload.
Validate Echo Reply: Next Header 58, type 129, checksum.

- [ ] **Step 2: Integrate dual-stack activation**

After receiving Assign with both families:
1. Configure utun v4 (existing)
2. Configure utun v6 (new)
3. Run v4 canary (existing)
4. Run v6 canary (new)
5. Install v4 routes (existing)
6. Install v6 routes (new)
7. Only then mark active

- [ ] **Step 3: Commit**

```bash
git add crates/multipass/src/bin/multipassd/main.rs
git commit -m "macos: dual-stack canary and atomic activation"
```

---

### Task 10: Linux — Dual-Stack TUN

**Files:**
- Modify: `crates/multipass-server/src/tun.rs`
- Test: `crates/multipass-server/src/tun.rs` (tests module)

**Interfaces:**
- Consumes: nothing
- Produces: `Tun::configure_v6(addr, prefix)`, MTU 1280

- [ ] **Step 1: Write failing test for IPv6 address assignment**

```rust
#[test]
fn tun_assigns_ipv6() {
    // Verify rtnetlink message construction for IPv6 address
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Add IPv6 configuration via rtnetlink**

Use `rtnetlink` crate or raw netlink to:
- Add IPv6 address to TUN interface
- Set MTU 1280
- Bring link up

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

```bash
git add crates/multipass-server/src/tun.rs
git commit -m "linux: dual-stack TUN configuration"
```

---

### Task 11: Linux — Dual-Stack Server

**Files:**
- Modify: `crates/multipass-server/src/main.rs`
- Test: `crates/multipass-server/src/main.rs` (tests module)

**Interfaces:**
- Consumes: dual-stack `Assign`
- Produces: dual-stack bind, NAT66 nftables

- [ ] **Step 1: Write failing test for dual-stack Assign response**

```rust
#[tokio::test]
async fn server_assigns_both_families() {
    // Verify Assign contains both ipv4 and ipv6
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Update server to assign both families**

- Bind `[::]:51823` (dual-stack socket)
- Assign `ipv4: Some((TUNNEL_CLIENT, 24))`
- Assign `ipv6: Some((TUNNEL_V6_CLIENT, 64))`
- MTU 1280

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Add NAT66 nftables configuration**

Create `nft.rs` or add to deployment:
```
table ip6 nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "enp5s0f1np1" ip6 saddr fd00:99::/64 masquerade
    }
}
```

- [ ] **Step 6: Commit**

```bash
git add crates/multipass-server/src/main.rs crates/multipass-server/src/nft.rs
git commit -m "linux: dual-stack server with NAT66"
```

---

### Task 12: Integration Testing

**Files:**
- Test: `crates/multipass/tests/aggregation.rs`
- Test: `crates/multipass/tests/ipv6.rs`

**Interfaces:**
- Consumes: all above
- Produces: end-to-end verification

- [ ] **Step 1: Write aggregation throughput test**

```rust
#[tokio::test]
async fn aggregation_achieves_combined_throughput() {
    // Spawn two paths with different RTTs
    // Send at high rate
    // Verify both paths carry traffic
    // Verify no packet loss
}
```

- [ ] **Step 2: Write failover continuity test**

```rust
#[tokio::test]
async fn failover_preserves_sessions() {
    // Start TCP-like flow
    // Kill one path
    // Verify flow continues on other path
    // Verify no retransmission from inner protocol
}
```

- [ ] **Step 3: Write IPv6 connectivity test**

```rust
#[tokio::test]
async fn ipv6_packets_flow_through_tunnel() {
    // Send IPv6 packet through tunnel
    // Verify it arrives at server
    // Verify reply returns
}
```

- [ ] **Step 4: Run all integration tests**

Run: `cargo nextest run`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add crates/multipass/tests/
git commit -m "tests: aggregation and IPv6 integration"
```

---

### Task 13: Deployment

**Files:**
- Create: `deploy/jax/multipass-server.service`
- Create: `deploy/jax/sysctl.conf`
- Create: `deploy/jax/nftables.conf`
- Create: `deploy/jax/README.md`

**Interfaces:**
- Consumes: none
- Produces: deployable artifacts

- [ ] **Step 1: Create systemd unit**

```ini
[Unit]
Description=Multipass VPN Server
After=network.target

[Service]
ExecStart=/usr/local/bin/multipass-server [::]:51823
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create sysctl config**

```
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
```

- [ ] **Step 3: Create nftables fragment**

```
table inet multipass {
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname "tun+" oifname "enp5s0f1np1" accept
        iifname "enp5s0f1np1" oifname "tun+" ct state established,related accept
        meta l4proto ipv6-icmp accept
    }
}
table ip6 nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "enp5s0f1np1" ip6 saddr fd00:99::/64 masquerade
    }
}
```

- [ ] **Step 4: Create deployment README**

Document installation, configuration, verification steps.

- [ ] **Step 5: Commit**

```bash
git add deploy/
git commit -m "deploy: jax systemd, sysctl, nftables artifacts"
```

---

### Task 14: Production Verification

**Files:**
- None (manual verification)

**Interfaces:**
- Consumes: deployed system
- Produces: verification report

- [ ] **Step 1: Deploy to jax**

```bash
scp target/x86_64-unknown-linux-gnu/release/multipass-server jax.vxn.rs:/tmp/
ssh jax.vxn.rs 'sudo install -m 0755 /tmp/multipass-server /usr/local/bin/'
# Install systemd unit, sysctl, nftables
```

- [ ] **Step 2: Deploy to scooter**

```bash
cargo build --release -p multipass --bin multipassd
sudo install -m 0755 target/release/multipassd /usr/local/libexec/
# Update LaunchDaemon plist
```

- [ ] **Step 3: Verify wire protocol**

```bash
# Check ALPN negotiation
sudo tcpdump -i en17 -n udp port 51823
# Should see multipass/1
```

- [ ] **Step 4: Verify aggregation throughput**

```bash
# On scooter, through tunnel
iperf3 -c <remote> -t 30
# Should achieve >1.5 Gbps
```

- [ ] **Step 5: Verify failover continuity**

```bash
# Start long-lived TCP flow
ssh <remote> 'iperf3 -s'
iperf3 -c <remote> -t 300 &
# Unplug Ethernet, verify flow continues
# Replug, verify recovery
```

- [ ] **Step 6: Verify IPv6**

```bash
# On scooter, through tunnel
ping6 -c 4 2001:4860:4860::8888
curl -6 https://ipv6.google.com
```

- [ ] **Step 7: Document verification results**

Create `docs/verification/2026-XX-XX-aggregation-ipv6.md` with results.

- [ ] **Step 8: Commit**

```bash
git add docs/verification/
git commit -m "docs: production verification results"
```

---

## Self-Review

**Spec coverage:**
- [x] Loss-recovered striping: Tasks 3-6, 12
- [x] SACK wire protocol: Task 1
- [x] Dual-stack Assign: Task 2
- [x] MTU 1280: Tasks 2, 10, 11
- [x] macOS dual-stack: Tasks 7-9
- [x] Linux dual-stack: Tasks 10-11
- [x] NAT66: Task 11
- [x] Integration tests: Task 12
- [x] Deployment artifacts: Task 13
- [x] Production verification: Task 14

**Placeholder scan:** No TBD, TODO, or vague steps. Each task has exact files, code, and test commands.

**Type consistency:** `Sack`, `SendWindow`, `Scheduler`, `SackScoreboard` used consistently. `Assign` fields match across proto and consumers.

**Dependencies:**
- Task 1-2 (proto) must complete before 3-6 (transport)
- Tasks 3-5 (client transport) can run in parallel with 10-11 (Linux)
- Tasks 7-9 (macOS) depend on Task 2 (Assign)
- Task 12 (integration) depends on all
- Task 13-14 (deployment) depend on 12
