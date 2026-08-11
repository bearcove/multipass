//! Selective acknowledgment scoreboard for aggregation.
//!
//! Tracks received sequence numbers in a sliding window and generates SACK
//! frames for the sender. Used by both client and server to acknowledge
//! received packets and enable retransmission of gaps.

/// Sliding-window scoreboard for received sequence numbers.
///
/// Fixed-size bit window; no allocation, no hashing. A `seq` is "new" if it is
/// ahead of the highest seen, or within the window behind it and not yet marked.
/// Out-of-window (very old) seqs are dropped as duplicates.
pub struct SackScoreboard {
    max_seq: u64,
    largest_contiguous: u64,
    started: bool,
    bits: [u64; Self::WORDS],
}

impl SackScoreboard {
    const WINDOW: u64 = 4096;
    const WORDS: usize = (Self::WINDOW / 64) as usize;

    pub fn new() -> Self {
        Self {
            max_seq: 0,
            largest_contiguous: 0,
            started: false,
            bits: [0; Self::WORDS],
        }
    }

    /// Record a received sequence number. Returns true if this is a new
    /// (previously unseen) sequence, false if duplicate or too old.
    pub fn insert(&mut self, seq: u64) -> bool {
        if seq <= self.largest_contiguous {
            return false;
        }
        if !self.started {
            self.started = true;
            self.max_seq = seq;
        } else if seq > self.max_seq {
            self.advance(seq - self.max_seq);
            self.max_seq = seq;
        } else {
            let back = self.max_seq - seq;
            if back >= Self::WINDOW {
                return false;
            }
            if self.get(seq) {
                return false;
            }
        }
        self.set(seq);
        self.advance_contiguous_prefix();
        true
    }

    /// Generate a SACK frame describing the current receive state.
    ///
    /// `largest_contiguous` is the highest sequence such that all sequences
    /// ≤ it have been received. `ranges` contains up to 8 selective ranges
    /// for out-of-order arrivals above `largest_contiguous`.
    pub fn generate_sack(&self) -> crate::Frame {
        if !self.started {
            return crate::Frame::Sack {
                largest_contiguous: 0,
                ranges: vec![],
            };
        }

        let largest_contiguous = self.largest_contiguous;
        let live_start = self
            .max_seq
            .saturating_sub(Self::WINDOW - 1)
            .max(largest_contiguous.saturating_add(1));

        let mut ranges = Vec::new();
        let mut range_start: Option<u64> = None;
        for seq in live_start..=self.max_seq {
            let received = self.get(seq);
            match (range_start, received) {
                (None, true) => range_start = Some(seq),
                (Some(start), false) => {
                    ranges.push((start, seq - 1));
                    range_start = None;
                    if ranges.len() >= 8 {
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(start) = range_start
            && ranges.len() < 8
        {
            ranges.push((start, self.max_seq));
        }

        crate::Frame::Sack {
            largest_contiguous,
            ranges,
        }
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

    fn advance_contiguous_prefix(&mut self) {
        while self.largest_contiguous < self.max_seq {
            let next = self.largest_contiguous + 1;
            if self.max_seq - next >= Self::WINDOW || !self.get(next) {
                break;
            }
            self.largest_contiguous = next;
        }
    }

    /// Advance the window by `shift`, clearing the slots being vacated so a
    /// later wrap doesn't read stale bits as received.
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

impl Default for SackScoreboard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoreboard_tracks_received() {
        let mut sb = SackScoreboard::new();
        assert!(sb.insert(1));
        assert!(sb.insert(2));
        assert!(sb.insert(4)); // gap at 3
        assert!(!sb.insert(1)); // duplicate
    }

    #[test]
    fn scoreboard_generates_sack() {
        let mut sb = SackScoreboard::new();
        sb.insert(1);
        sb.insert(2);
        sb.insert(4); // gap at 3

        let sack = sb.generate_sack();
        match sack {
            crate::Frame::Sack {
                largest_contiguous,
                ranges,
            } => {
                assert_eq!(largest_contiguous, 2);
                assert_eq!(ranges, vec![(4, 4)]);
            }
            _ => panic!("expected Sack frame"),
        }
    }

    #[test]
    fn scoreboard_empty() {
        let sb = SackScoreboard::new();
        let sack = sb.generate_sack();
        match sack {
            crate::Frame::Sack {
                largest_contiguous,
                ranges,
            } => {
                assert_eq!(largest_contiguous, 0);
                assert!(ranges.is_empty());
            }
            _ => panic!("expected Sack frame"),
        }
    }

    #[test]
    fn scoreboard_contiguous_prefix() {
        let mut sb = SackScoreboard::new();
        for i in 1..=10 {
            sb.insert(i);
        }
        let sack = sb.generate_sack();
        match sack {
            crate::Frame::Sack {
                largest_contiguous,
                ranges,
            } => {
                assert_eq!(largest_contiguous, 10);
                assert!(ranges.is_empty());
            }
            _ => panic!("expected Sack frame"),
        }
    }

    #[test]
    fn scoreboard_contiguous_prefix_never_regresses_after_wrap() {
        let mut sb = SackScoreboard::new();
        for seq in 1..=SackScoreboard::WINDOW {
            assert!(sb.insert(seq));
        }
        assert!(sb.insert(SackScoreboard::WINDOW * 2 + 1));

        let crate::Frame::Sack {
            largest_contiguous,
            ranges,
        } = sb.generate_sack()
        else {
            panic!("expected Sack frame");
        };
        assert_eq!(largest_contiguous, SackScoreboard::WINDOW);
        assert_eq!(
            ranges,
            vec![(
                SackScoreboard::WINDOW * 2 + 1,
                SackScoreboard::WINDOW * 2 + 1
            )]
        );
    }

    #[test]
    fn scoreboard_sack_scan_is_bounded_to_the_live_window() {
        let mut sb = SackScoreboard::new();
        assert!(sb.insert(1));
        assert!(sb.insert(1_000_000_001));

        let crate::Frame::Sack {
            largest_contiguous,
            ranges,
        } = sb.generate_sack()
        else {
            panic!("expected Sack frame");
        };
        assert_eq!(largest_contiguous, 1);
        assert_eq!(ranges, vec![(1_000_000_001, 1_000_000_001)]);
    }
}
