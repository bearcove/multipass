//! Sender-side retention window for loss-recovered aggregation.
//!
//! Every Data frame is retained until the peer's SACK confirms receipt. On a
//! SACK gap or path death, the retained copy is retransmitted on another path.
//! This is the mechanism that makes striping safe: a path failure cannot
//! destroy the only copy of a packet because ownership stays with the session
//! until peer receipt is proven.

use bytes::Bytes;
use std::collections::VecDeque;

/// Bounded ring of unacknowledged outbound packets, keyed by sequence number.
///
/// Sequences are dense and monotonically increasing, so the window is a ring
/// indexed by `seq - base_seq`. Retired (acked) entries are `None`.
pub struct SendWindow {
    capacity: usize,
    /// Sequence number of `entries[0]`.
    base_seq: u64,
    /// Ring of retained packets. `None` = acked/retired.
    entries: VecDeque<Option<Bytes>>,
    /// Highest sequence ever inserted.
    max_seq: u64,
    started: bool,
}

impl SendWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            base_seq: 0,
            entries: VecDeque::new(),
            max_seq: 0,
            started: false,
        }
    }

    /// Retain a packet for possible retransmission. Called once per outbound
    /// sequence, after the initial send.
    pub fn insert(&mut self, seq: u64, packet: Bytes) {
        if !self.started {
            self.started = true;
            self.base_seq = seq;
            self.max_seq = seq;
            self.entries.push_back(Some(packet));
            return;
        }
        debug_assert!(seq > self.max_seq, "sequences must be monotonically increasing");
        // Extend the ring with None for any gap (shouldn't happen, but be safe)
        while self.max_seq + 1 < seq {
            self.entries.push_back(None);
            self.max_seq += 1;
        }
        self.entries.push_back(Some(packet));
        self.max_seq = seq;
        // Enforce capacity by dropping oldest unacked (this loses recoverability;
        // callers must apply backpressure before this happens)
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
            self.base_seq += 1;
        }
    }

    /// Process a SACK from the peer. Retires acked packets and returns the
    /// sequence numbers that need retransmission (gaps below the highest
    /// acked sequence that remain unacknowledged).
    pub fn ack(&mut self, largest_contiguous: u64, ranges: &[(u64, u64)]) -> Vec<u64> {
        // Retire everything <= largest_contiguous
        if self.started && largest_contiguous >= self.base_seq {
            let retire_up_to = largest_contiguous.min(self.max_seq);
            for seq in self.base_seq..=retire_up_to {
                let idx = (seq - self.base_seq) as usize;
                if idx < self.entries.len() {
                    self.entries[idx] = None;
                }
            }
        }
        // Retire selective ranges
        for &(start, end) in ranges {
            if !self.started {
                break;
            }
            for seq in start..=end.min(self.max_seq) {
                if seq < self.base_seq {
                    continue;
                }
                let idx = (seq - self.base_seq) as usize;
                if idx < self.entries.len() {
                    self.entries[idx] = None;
                }
            }
        }
        // Find gaps: unacked sequences at or below the highest sequence the
        // peer has seen. The highest seen is max(largest_contiguous, max range end).
        let highest_seen = ranges
            .iter()
            .map(|&(_, end)| end)
            .max()
            .unwrap_or(largest_contiguous);
        let mut gaps = Vec::new();
        if self.started {
            for seq in self.base_seq..=highest_seen.min(self.max_seq) {
                let idx = (seq - self.base_seq) as usize;
                if idx < self.entries.len() && self.entries[idx].is_some() {
                    gaps.push(seq);
                }
            }
        }
        gaps
    }

    /// Get a retained packet by sequence, for retransmission.
    pub fn get(&self, seq: u64) -> Option<Bytes> {
        if !self.started || seq < self.base_seq || seq > self.max_seq {
            return None;
        }
        let idx = (seq - self.base_seq) as usize;
        self.entries.get(idx).and_then(|e| e.clone())
    }

    /// All currently unacknowledged sequences (for path-death retransmission).
    pub fn unacked(&self) -> Vec<u64> {
        if !self.started {
            return Vec::new();
        }
        (self.base_seq..=self.max_seq)
            .filter(|&seq| {
                let idx = (seq - self.base_seq) as usize;
                idx < self.entries.len() && self.entries[idx].is_some()
            })
            .collect()
    }

    /// Whether the window has reached capacity (callers must apply backpressure).
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// Number of retained (unacked) packets.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_window_retains_until_ack() {
        let mut sw = SendWindow::new(4096);
        sw.insert(1, Bytes::from_static(b"pkt1"));
        sw.insert(2, Bytes::from_static(b"pkt2"));
        assert_eq!(sw.unacked(), vec![1, 2]);

        // ACK seq 1
        let gaps = sw.ack(1, &[]);
        assert_eq!(sw.unacked(), vec![2]);
        assert!(gaps.is_empty());
    }

    #[test]
    fn send_window_detects_gaps() {
        let mut sw = SendWindow::new(4096);
        sw.insert(1, Bytes::from_static(b"pkt1"));
        sw.insert(2, Bytes::from_static(b"pkt2"));
        sw.insert(3, Bytes::from_static(b"pkt3"));

        // SACK says 1 and 3 received, gap at 2
        let gaps = sw.ack(1, &[(3, 3)]);
        assert_eq!(gaps, vec![2]);
        // seq 2 still retained for retransmission
        assert_eq!(sw.get(2), Some(Bytes::from_static(b"pkt2")));
        // seqs 1 and 3 retired
        assert_eq!(sw.unacked(), vec![2]);
    }

    #[test]
    fn send_window_get_returns_retained_packet() {
        let mut sw = SendWindow::new(4096);
        sw.insert(5, Bytes::from_static(b"pkt5"));
        assert_eq!(sw.get(5), Some(Bytes::from_static(b"pkt5")));
        assert_eq!(sw.get(4), None);
        assert_eq!(sw.get(6), None);
    }

    #[test]
    fn send_window_full_detection() {
        let mut sw = SendWindow::new(2);
        assert!(!sw.is_full());
        sw.insert(1, Bytes::from_static(b"a"));
        sw.insert(2, Bytes::from_static(b"b"));
        assert!(sw.is_full());
    }
}
