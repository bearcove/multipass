//! multipass wire format — the contract between client (scooter) and server
//! (router). No I/O here; just framing, dedup, and control messages. Both sides
//! depend on this crate; keep it minimal and allocation-free on the hot path.
//!
//! One QUIC datagram carries exactly one `Frame`. The tunnel sends each Data
//! frame on BOTH connections (active-active); the receiver dedups by `seq`.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod sack;
mod scheduler;
mod send_window;
pub use sack::SackScoreboard;
pub use scheduler::Scheduler;
pub use send_window::SendWindow;

/// Which of the two active-active connections a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    Wired,
    Wifi,
}

impl PathKind {
    /// Both paths, in a stable order.
    pub const ALL: [PathKind; 2] = [PathKind::Wired, PathKind::Wifi];

    /// Human label for logs / status.
    pub fn label(self) -> &'static str {
        match self {
            PathKind::Wired => "wired",
            PathKind::Wifi => "wifi",
        }
    }
}

/// ALPN for wire protocol version 2. Version 2 requires `Assign.server_version`.
pub const ALPN: &[u8] = b"multipass/2";

/// Well-known tunnel subnet layout. Server is .1, first client is .2.
pub const TUNNEL_SERVER: Ipv4Addr = Ipv4Addr::new(10, 10, 99, 1);
pub const TUNNEL_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 99, 2);
pub const TUNNEL_PREFIX: u8 = 24;

/// IPv6 tunnel prefix (ULA, NAT66 mode). Server is ::1, client is ::2.
pub const TUNNEL_V6_PREFIX: u8 = 64;
pub const TUNNEL_V6_SERVER: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 1);
pub const TUNNEL_V6_CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 2);

/// Conservative inner MTU for QUIC DATAGRAM. 1280 is the IPv6 minimum link MTU;
/// noq's PMTUD converges to ~1414 on a 1500-byte underlay, so 1280 + 9 bytes
/// framing fits after convergence.
pub const TUNNEL_MTU: u16 = 1280;

/// Frame type tag (first byte of every datagram).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// A raw IP packet from the tunnel. Payload: [seq u64][ip packet].
    Data = 0,
    /// Client -> server handshake. Payload: [client_nonce u64].
    Hello = 1,
    /// Server -> client address assignment and build identity.
    /// Payload: [addr flags + values][mtu u16][dns][version_len u16][version bytes].
    Assign = 2,
    /// Liveness probe either direction. Payload: [nonce u64].
    Ping = 3,
    /// Liveness reply. Payload: [nonce u64] (echoed).
    Pong = 4,
    /// Selective acknowledgment. Payload: [largest_contiguous u64][range_count u8][ranges...].
    Sack = 5,
}

impl Tag {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Tag::Data,
            1 => Tag::Hello,
            2 => Tag::Assign,
            3 => Tag::Ping,
            4 => Tag::Pong,
            5 => Tag::Sack,
            _ => return None,
        })
    }
}

/// A decoded frame. `Data`'s packet is owned Bytes.
#[derive(Debug, Clone)]
pub enum Frame {
    Data {
        seq: u64,
        packet: Bytes,
    },
    Hello {
        client_nonce: u64,
    },
    Assign {
        ipv4: Option<(Ipv4Addr, u8)>,
        ipv6: Option<(Ipv6Addr, u8)>,
        mtu: u16,
        dns: Vec<IpAddr>,
        server_version: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Sack {
        largest_contiguous: u64,
        ranges: Vec<(u64, u64)>,
    },
}

/// Encode a frame into a fresh buffer ready to send as one datagram.
pub fn encode(frame: &Frame) -> Bytes {
    let mut out = BytesMut::new();
    match frame {
        Frame::Data { seq, packet } => {
            out.reserve(1 + 8 + packet.len());
            out.put_u8(Tag::Data as u8);
            out.put_u64(*seq);
            out.extend_from_slice(packet);
        }
        Frame::Hello { client_nonce } => {
            out.put_u8(Tag::Hello as u8);
            out.put_u64(*client_nonce);
        }
        Frame::Assign {
            ipv4,
            ipv6,
            mtu,
            dns,
            server_version,
        } => {
            out.put_u8(Tag::Assign as u8);
            // flags: bit 0 = ipv4 present, bit 1 = ipv6 present
            let mut flags = 0u8;
            if ipv4.is_some() {
                flags |= 1;
            }
            if ipv6.is_some() {
                flags |= 2;
            }
            out.put_u8(flags);
            if let Some((addr, prefix)) = ipv4 {
                out.put_u32(u32::from(*addr));
                out.put_u8(*prefix);
            }
            if let Some((addr, prefix)) = ipv6 {
                out.put_u128(u128::from(*addr));
                out.put_u8(*prefix);
            }
            out.put_u16(*mtu);
            out.put_u8(dns.len() as u8);
            for addr in dns {
                match addr {
                    IpAddr::V4(a) => {
                        out.put_u8(4);
                        out.put_u32(u32::from(*a));
                    }
                    IpAddr::V6(a) => {
                        out.put_u8(6);
                        out.put_u128(u128::from(*a));
                    }
                }
            }
            let version = server_version.as_bytes();
            let version_len = u16::try_from(version.len()).expect("server version exceeds u16");
            out.put_u16(version_len);
            out.extend_from_slice(version);
        }
        Frame::Ping { nonce } => {
            out.put_u8(Tag::Ping as u8);
            out.put_u64(*nonce);
        }
        Frame::Pong { nonce } => {
            out.put_u8(Tag::Pong as u8);
            out.put_u64(*nonce);
        }
        Frame::Sack {
            largest_contiguous,
            ranges,
        } => {
            out.put_u8(Tag::Sack as u8);
            out.put_u64(*largest_contiguous);
            out.put_u8(ranges.len() as u8);
            for &(start, end) in ranges {
                out.put_u64(start);
                out.put_u64(end);
            }
        }
    }
    out.freeze()
}

/// Decode one datagram into a frame. Returns None on malformed input.
pub fn decode(mut buf: &[u8]) -> Option<Frame> {
    if buf.is_empty() {
        return None;
    }
    let tag = Tag::from_u8(buf.get_u8())?;
    match tag {
        Tag::Data => {
            if buf.remaining() < 8 {
                return None;
            }
            let seq = buf.get_u64();
            let packet = Bytes::copy_from_slice(buf);
            Some(Frame::Data { seq, packet })
        }
        Tag::Hello => {
            if buf.remaining() < 8 {
                return None;
            }
            Some(Frame::Hello {
                client_nonce: buf.get_u64(),
            })
        }
        Tag::Assign => {
            if buf.remaining() < 3 {
                return None;
            }
            let flags = buf.get_u8();
            let ipv4 = if flags & 1 != 0 {
                if buf.remaining() < 5 {
                    return None;
                }
                let addr = Ipv4Addr::from(buf.get_u32());
                let prefix = buf.get_u8();
                Some((addr, prefix))
            } else {
                None
            };
            let ipv6 = if flags & 2 != 0 {
                if buf.remaining() < 17 {
                    return None;
                }
                let addr = Ipv6Addr::from(buf.get_u128());
                let prefix = buf.get_u8();
                Some((addr, prefix))
            } else {
                None
            };
            if buf.remaining() < 3 {
                return None;
            }
            let mtu = buf.get_u16();
            let dns_count = buf.get_u8() as usize;
            let mut dns = Vec::with_capacity(dns_count);
            for _ in 0..dns_count {
                if buf.remaining() < 1 {
                    return None;
                }
                let family = buf.get_u8();
                match family {
                    4 => {
                        if buf.remaining() < 4 {
                            return None;
                        }
                        dns.push(IpAddr::V4(Ipv4Addr::from(buf.get_u32())));
                    }
                    6 => {
                        if buf.remaining() < 16 {
                            return None;
                        }
                        dns.push(IpAddr::V6(Ipv6Addr::from(buf.get_u128())));
                    }
                    _ => return None,
                }
            }
            if buf.remaining() < 2 {
                return None;
            }
            let version_len = buf.get_u16() as usize;
            if buf.remaining() != version_len {
                return None;
            }
            let server_version = String::from_utf8(buf.copy_to_bytes(version_len).to_vec()).ok()?;
            Some(Frame::Assign {
                ipv4,
                ipv6,
                mtu,
                dns,
                server_version,
            })
        }
        Tag::Ping => {
            if buf.remaining() < 8 {
                return None;
            }
            Some(Frame::Ping {
                nonce: buf.get_u64(),
            })
        }
        Tag::Pong => {
            if buf.remaining() < 8 {
                return None;
            }
            Some(Frame::Pong {
                nonce: buf.get_u64(),
            })
        }
        Tag::Sack => {
            if buf.remaining() < 9 {
                return None;
            }
            let largest_contiguous = buf.get_u64();
            let range_count = buf.get_u8() as usize;
            if buf.remaining() < range_count * 16 {
                return None;
            }
            let mut ranges = Vec::with_capacity(range_count);
            for _ in 0..range_count {
                let start = buf.get_u64();
                let end = buf.get_u64();
                ranges.push((start, end));
            }
            Some(Frame::Sack {
                largest_contiguous,
                ranges,
            })
        }
    }
}

/// Sliding-window dedup for active-active delivery. Both connections carry
/// every Data frame; the receiver keeps only the first of each `seq`.
///
/// Fixed-size bit window; no allocation, no hashing. A `seq` is "new" if it is
/// ahead of the highest seen, or within the window behind it and not yet marked.
/// Out-of-window (very old) seqs are dropped as dup.
pub struct Dedup {
    max_seq: u64,
    started: bool,
    bits: [u64; Dedup::WORDS],
}

impl Dedup {
    const WINDOW: u64 = 4096;
    const WORDS: usize = (Self::WINDOW / 64) as usize;

    pub fn new() -> Self {
        Self {
            max_seq: 0,
            started: false,
            bits: [0; Self::WORDS],
        }
    }

    /// Returns true if this seq is new (first time seen), false if duplicate
    /// or too old to track.
    pub fn insert(&mut self, seq: u64) -> bool {
        if !self.started {
            self.started = true;
            self.max_seq = seq;
            self.set(seq);
            return true;
        }
        if seq > self.max_seq {
            self.advance(seq - self.max_seq);
            self.max_seq = seq;
        } else {
            let back = self.max_seq - seq;
            if back >= Self::WINDOW {
                return false; // too old
            }
            if self.get(seq) {
                return false; // duplicate
            }
        }
        self.set(seq);
        true
    }

    fn pos(seq: u64) -> (usize, u64) {
        let idx = (seq % Self::WINDOW) as usize;
        (idx / 64, 1u64 << (idx % 64))
    }
    fn get(&self, seq: u64) -> bool {
        let (w, m) = Self::pos(seq);
        self.bits[w] & m != 0
    }
    fn set(&mut self, seq: u64) {
        let (w, m) = Self::pos(seq);
        self.bits[w] |= m;
    }
    /// Advance the window by `shift`, clearing the slots being vacated so a
    /// later wrap doesn't read stale bits as duplicates.
    fn advance(&mut self, shift: u64) {
        if shift >= Self::WINDOW {
            self.bits = [0; Self::WORDS];
            return;
        }
        for s in (self.max_seq + 1)..=(self.max_seq + shift) {
            let (w, m) = Self::pos(s);
            self.bits[w] &= !m;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorderInsert {
    Rejected,
    Admitted,
    AdmittedAfterSkipping { first: u64, last: u64 },
}

/// Bounded receive-side buffer that converts path arrival order into logical
/// packet order before packets reach the TUN. Sequence numbers start at one.
pub struct ReorderBuffer<T> {
    next_seq: u64,
    slots: Vec<Option<T>>,
}

impl<T> ReorderBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "reorder capacity must be positive");
        Self {
            next_seq: 1,
            slots: (0..capacity).map(|_| None).collect(),
        }
    }

    /// Retain a packet without ever dropping admitted data. When a packet is
    /// more than 75% of the window ahead, advance past only missing leading
    /// sequences before the buffer can saturate, preserving its suffix.
    pub fn insert(&mut self, seq: u64, value: T) -> ReorderInsert {
        let Some(mut offset) = seq.checked_sub(self.next_seq) else {
            return ReorderInsert::Rejected;
        };
        let mut skipped = None;
        let recovery_threshold = (self.slots.len() * 3 / 4).max(1) as u64;
        if offset >= recovery_threshold && self.slots[0].is_none() {
            let first = self.next_seq;
            while offset >= recovery_threshold && self.slots[0].is_none() {
                self.advance_one();
                offset -= 1;
            }
            skipped = Some((first, self.next_seq - 1));
        }
        if offset >= self.slots.len() as u64 {
            return ReorderInsert::Rejected;
        }
        let slot = &mut self.slots[offset as usize];
        if slot.is_some() {
            return ReorderInsert::Rejected;
        }
        *slot = Some(value);
        match skipped {
            Some((first, last)) => ReorderInsert::AdmittedAfterSkipping { first, last },
            None => ReorderInsert::Admitted,
        }
    }

    fn advance_one(&mut self) {
        self.slots.rotate_left(1);
        *self.slots.last_mut().expect("positive capacity") = None;
        self.next_seq += 1;
    }

    /// Release the next contiguous packet, if present.
    pub fn pop_ready(&mut self) -> Option<T> {
        let value = self.slots[0].take()?;
        self.advance_one();
        Some(value)
    }

    /// Abandon only the missing prefix before the first buffered packet. Used
    /// by a receiver timer after retransmission has had time to arrive.
    pub fn skip_missing_prefix(&mut self) -> Option<(u64, u64)> {
        if self.slots[0].is_some() || self.slots.iter().all(Option::is_none) {
            return None;
        }
        let first = self.next_seq;
        while self.slots[0].is_none() && self.slots.iter().any(Option::is_some) {
            self.advance_one();
        }
        Some((first, self.next_seq - 1))
    }

    pub fn has_gap(&self) -> bool {
        self.slots[0].is_none() && self.slots.iter().any(Option::is_some)
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn occupancy(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn buffered_span(&self) -> Option<(u64, u64)> {
        let first = self.slots.iter().position(Option::is_some)? as u64;
        let last = self.slots.iter().rposition(Option::is_some)? as u64;
        Some((self.next_seq + first, self.next_seq + last))
    }
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reorder_buffer_releases_only_contiguous_packets() {
        let mut reorder = ReorderBuffer::new(8);

        assert_eq!(reorder.insert(1, "one"), ReorderInsert::Admitted);
        assert_eq!(reorder.pop_ready(), Some("one"));
        assert_eq!(reorder.insert(3, "three"), ReorderInsert::Admitted);
        assert_eq!(reorder.pop_ready(), None);
        assert_eq!(reorder.insert(2, "two"), ReorderInsert::Admitted);
        assert_eq!(reorder.pop_ready(), Some("two"));
        assert_eq!(reorder.pop_ready(), Some("three"));
        assert_eq!(reorder.pop_ready(), None);
    }

    #[test]
    fn reorder_buffer_skips_missing_prefix_before_capacity_is_exhausted() {
        let mut reorder = ReorderBuffer::new(8);
        for seq in 2..=6 {
            assert_eq!(reorder.insert(seq, seq), ReorderInsert::Admitted);
        }
        assert_eq!(
            reorder.insert(7, 7),
            ReorderInsert::AdmittedAfterSkipping { first: 1, last: 1 }
        );
        assert_eq!(reorder.insert(8, 8), ReorderInsert::Admitted);
        assert_eq!(reorder.pop_ready(), Some(2));
    }

    #[test]
    fn reorder_buffer_advances_missing_prefix_at_window_boundary() {
        let mut reorder = ReorderBuffer::new(4);

        assert_eq!(reorder.insert(2, "two"), ReorderInsert::Admitted);
        assert_eq!(reorder.insert(3, "three"), ReorderInsert::Admitted);
        assert_eq!(
            reorder.insert(4, "four"),
            ReorderInsert::AdmittedAfterSkipping { first: 1, last: 1 }
        );
        assert_eq!(reorder.insert(5, "five"), ReorderInsert::Admitted);
        assert_eq!(reorder.pop_ready(), Some("two"));
        assert_eq!(reorder.pop_ready(), Some("three"));
        assert_eq!(reorder.pop_ready(), Some("four"));
        assert_eq!(reorder.pop_ready(), Some("five"));
    }

    #[test]
    fn reorder_buffer_timer_can_release_buffered_suffix() {
        let mut reorder = ReorderBuffer::new(8);
        assert_eq!(reorder.insert(2, "two"), ReorderInsert::Admitted);
        assert_eq!(reorder.insert(3, "three"), ReorderInsert::Admitted);

        assert_eq!(reorder.skip_missing_prefix(), Some((1, 1)));
        assert_eq!(reorder.pop_ready(), Some("two"));
        assert_eq!(reorder.pop_ready(), Some("three"));
        assert_eq!(reorder.skip_missing_prefix(), None);
    }

    #[test]
    fn reorder_buffer_rejects_duplicates_and_old_packets() {
        let mut reorder = ReorderBuffer::new(4);

        assert_eq!(reorder.insert(2, "two"), ReorderInsert::Admitted);
        assert_eq!(reorder.insert(2, "duplicate"), ReorderInsert::Rejected);
        assert_eq!(reorder.insert(1, "one"), ReorderInsert::Admitted);
        assert_eq!(reorder.pop_ready(), Some("one"));
        assert_eq!(reorder.pop_ready(), Some("two"));
        assert_eq!(reorder.insert(1, "old"), ReorderInsert::Rejected);
    }

    #[test]
    fn alpn_identifies_assign_server_version_contract() {
        assert_eq!(ALPN, b"multipass/2");
    }

    #[test]
    fn data_roundtrip() {
        let pkt = Bytes::from_static(&[0x45, 0x00, 0x00, 0x3c, 1, 2, 3]);
        let f = Frame::Data {
            seq: 42,
            packet: pkt.clone(),
        };
        let enc = encode(&f);
        match decode(&enc).unwrap() {
            Frame::Data { seq, packet } => {
                assert_eq!(seq, 42);
                assert_eq!(packet, pkt);
            }
            _ => panic!("wrong frame"),
        }
    }

    #[test]
    fn control_roundtrip() {
        for f in [
            Frame::Hello {
                client_nonce: 0xdeadbeef,
            },
            Frame::Assign {
                ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
                ipv6: None,
                mtu: TUNNEL_MTU,
                dns: vec![],
                server_version: "test-server".into(),
            },
            Frame::Ping { nonce: 7 },
            Frame::Pong { nonce: 7 },
        ] {
            let enc = encode(&f);
            let dec = decode(&enc).unwrap();
            assert_eq!(format!("{dec:?}"), format!("{f:?}"));
        }
    }

    #[test]
    fn sack_frame_roundtrip() {
        let sack = Frame::Sack {
            largest_contiguous: 100,
            ranges: vec![(95, 98), (85, 90)],
        };
        let encoded = encode(&sack);
        let decoded = decode(&encoded).unwrap();
        match decoded {
            Frame::Sack {
                largest_contiguous,
                ranges,
            } => {
                assert_eq!(largest_contiguous, 100);
                assert_eq!(ranges, vec![(95, 98), (85, 90)]);
            }
            _ => panic!("wrong frame"),
        }
    }

    #[test]
    fn assign_dual_stack_roundtrip() {
        use std::net::Ipv6Addr;
        let assign = Frame::Assign {
            ipv4: Some((Ipv4Addr::new(10, 10, 99, 2), 24)),
            ipv6: Some((Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 2), 64)),
            mtu: 1280,
            dns: vec![],
            server_version: "test-server".into(),
        };
        let encoded = encode(&assign);
        let decoded = decode(&encoded).unwrap();
        match decoded {
            Frame::Assign {
                ipv4,
                ipv6,
                mtu,
                dns,
                server_version,
            } => {
                assert_eq!(ipv4, Some((Ipv4Addr::new(10, 10, 99, 2), 24)));
                assert_eq!(
                    ipv6,
                    Some((Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 2), 64))
                );
                assert_eq!(mtu, 1280);
                assert!(dns.is_empty());
                assert_eq!(server_version, "test-server");
            }
            _ => panic!("wrong frame"),
        }
    }

    #[test]
    fn assign_roundtrip_preserves_server_version() {
        let assign = Frame::Assign {
            ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
            ipv6: None,
            mtu: TUNNEL_MTU,
            dns: vec![],
            server_version: "server-commit-123".into(),
        };

        let decoded = decode(&encode(&assign)).unwrap();
        match decoded {
            Frame::Assign { server_version, .. } => {
                assert_eq!(server_version, "server-commit-123");
            }
            _ => panic!("expected Assign"),
        }
    }

    #[test]
    fn assign_decode_rejects_truncated_server_version() {
        let assign = Frame::Assign {
            ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
            ipv6: None,
            mtu: TUNNEL_MTU,
            dns: vec![],
            server_version: "server-commit-123".into(),
        };
        let encoded = encode(&assign);

        assert!(decode(&encoded[..encoded.len() - 1]).is_none());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[99]).is_none()); // unknown tag
        assert!(decode(&[0, 1, 2]).is_none()); // data too short for seq
    }

    #[test]
    fn dedup_first_copy_only() {
        let mut d = Dedup::new();
        assert!(d.insert(1));
        assert!(!d.insert(1)); // dup
        assert!(d.insert(2));
        assert!(!d.insert(2));
    }

    #[test]
    fn dedup_out_of_order_within_window() {
        let mut d = Dedup::new();
        assert!(d.insert(100));
        assert!(d.insert(105)); // jump ahead
        assert!(d.insert(102)); // backfill within window
        assert!(!d.insert(102)); // dup
        assert!(!d.insert(100)); // dup
    }

    #[test]
    fn dedup_drops_too_old() {
        let mut d = Dedup::new();
        assert!(d.insert(1));
        assert!(d.insert(1 + Dedup::WINDOW + 10));
        // seq 1 is now out of window
        assert!(!d.insert(1));
    }
}
