//! multipass wire format — the contract between client (scooter) and server
//! (router). No I/O here; just framing, dedup, and control messages. Both sides
//! depend on this crate; keep it minimal and allocation-free on the hot path.
//!
//! One QUIC datagram carries exactly one `Frame`. The tunnel sends each Data
//! frame on BOTH connections (active-active); the receiver dedups by `seq`.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;

mod sack;
pub use sack::SackScoreboard;

/// ALPN for the multipass tunnel connection.
pub const ALPN: &[u8] = b"multipass/0";

/// Well-known tunnel subnet layout. Server is .1, first client is .2.
pub const TUNNEL_SERVER: Ipv4Addr = Ipv4Addr::new(10, 10, 99, 1);
pub const TUNNEL_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 99, 2);
pub const TUNNEL_PREFIX: u8 = 24;
/// Conservative inner MTU for QUIC DATAGRAM. noq initially permits 1162-byte
/// application datagrams; the Data frame adds a one-byte tag and u64 sequence.
pub const TUNNEL_MTU: u16 = 1153;

/// Frame type tag (first byte of every datagram).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// A raw IP packet from the tunnel. Payload: [seq u64][ip packet].
    Data = 0,
    /// Client -> server handshake. Payload: [client_nonce u64].
    Hello = 1,
    /// Server -> client address assignment.
    /// Payload: [addr u32][prefix u8][mtu u16].
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
        addr: Ipv4Addr,
        prefix: u8,
        mtu: u16,
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
        Frame::Assign { addr, prefix, mtu } => {
            out.put_u8(Tag::Assign as u8);
            out.put_u32(u32::from(*addr));
            out.put_u8(*prefix);
            out.put_u16(*mtu);
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
            if buf.remaining() < 7 {
                return None;
            }
            let addr = Ipv4Addr::from(buf.get_u32());
            let prefix = buf.get_u8();
            let mtu = buf.get_u16();
            Some(Frame::Assign { addr, prefix, mtu })
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

impl Default for Dedup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                addr: TUNNEL_CLIENT,
                prefix: TUNNEL_PREFIX,
                mtu: TUNNEL_MTU,
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
