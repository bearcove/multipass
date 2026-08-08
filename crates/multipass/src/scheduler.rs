//! Congestion-aware path scheduler for aggregation.
//!
//! Unlike the removed weighted-WRR scheduler (which striped blindly and lost
//! packets on path failure), this scheduler exists only to *estimate* which
//! path delivers a packet soonest. Correctness comes from the SendWindow +
//! SACK retransmission layer above; the scheduler is purely an optimization
//! for throughput and latency.
//!
//! Each path's cost is its estimated delivery time: RTT/2 (one-way) plus a
//! queueing term derived from the path's available datagram send buffer. The
//! scheduler picks the lowest-cost ready path per packet, which naturally
//! stripes in proportion to each path's real-time capacity.

use crate::PathKind;
use std::time::Duration;

/// Per-path scheduling inputs, updated from probes and send observations.
#[derive(Debug, Clone, Copy)]
struct PathState {
    /// Last measured round-trip time.
    rtt: Option<Duration>,
    /// Whether the path is alive and ready for data.
    eligible: bool,
    /// EWMA of recent send rate in bytes/sec (for queueing estimate).
    send_rate_bps: f64,
    /// Last observed datagram send buffer space in bytes.
    queue_space: usize,
}

impl Default for PathState {
    fn default() -> Self {
        Self {
            rtt: None,
            eligible: false,
            send_rate_bps: 0.0,
            queue_space: usize::MAX,
        }
    }
}

/// Picks the path with the lowest estimated delivery time for each packet.
pub struct Scheduler {
    paths: [PathState; 2],
}

fn idx(p: PathKind) -> usize {
    match p {
        PathKind::Wired => 0,
        PathKind::Wifi => 1,
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            paths: [PathState::default(), PathState::default()],
        }
    }

    /// Mark a path eligible (alive + ready) or not.
    pub fn set_eligible(&mut self, path: PathKind, eligible: bool) {
        self.paths[idx(path)].eligible = eligible;
    }

    /// Record a measured RTT for a path.
    pub fn note_rtt(&mut self, path: PathKind, rtt: Duration) {
        self.paths[idx(path)].rtt = Some(rtt);
    }

    /// Record the current datagram send buffer space for a path.
    pub fn note_queue_space(&mut self, path: PathKind, bytes: usize) {
        self.paths[idx(path)].queue_space = bytes;
    }

    /// Record a send of `bytes` on a path (updates the EWMA send rate).
    pub fn note_send(&mut self, path: PathKind, bytes: usize, elapsed: Duration) {
        let p = &mut self.paths[idx(path)];
        if elapsed.as_secs_f64() > 0.0 {
            let rate = bytes as f64 / elapsed.as_secs_f64();
            // EWMA with alpha = 0.2
            p.send_rate_bps = if p.send_rate_bps == 0.0 {
                rate
            } else {
                0.8 * p.send_rate_bps + 0.2 * rate
            };
        }
    }

    /// Estimated one-way delivery cost for a packet on `path`. Lower is
    /// better. Returns `None` if the path is not eligible.
    ///
    /// Cost = RTT/2, plus a penalty as the send buffer fills. We only observe
    /// free space, so a nearly-full buffer (small free space) adds latency
    /// proportional to how close it is to eviction. This keeps a congested
    /// path from absorbing more traffic until it drains.
    fn cost(&self, path: PathKind) -> Option<Duration> {
        let p = &self.paths[idx(path)];
        if !p.eligible {
            return None;
        }
        let one_way = p.rtt.unwrap_or(Duration::from_millis(1)) / 2;
        // Penalize a path whose send buffer is nearly exhausted. noq's default
        // send buffer is 1 MiB; below ~64 KiB free we treat the path as
        // congested and scale the penalty up sharply.
        const FULL: f64 = 1024.0 * 1024.0;
        const LOW: f64 = 64.0 * 1024.0;
        let free = p.queue_space as f64;
        let penalty = if free >= FULL {
            Duration::ZERO
        } else if free <= LOW {
            Duration::from_millis(50) // heavily congested
        } else {
            // Linear 0..10ms across the LOW..FULL band
            let frac = (FULL - free) / (FULL - LOW);
            Duration::from_secs_f64(frac * 0.010)
        };
        Some(one_way + penalty)
    }

    /// Pick the best path for a packet. Returns `None` if no path is eligible.
    pub fn pick(&mut self) -> Option<PathKind> {
        let wired = self.cost(PathKind::Wired);
        let wifi = self.cost(PathKind::Wifi);
        match (wired, wifi) {
            (Some(w), Some(f)) => Some(if w <= f { PathKind::Wired } else { PathKind::Wifi }),
            (Some(_), None) => Some(PathKind::Wired),
            (None, Some(_)) => Some(PathKind::Wifi),
            (None, None) => None,
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_picks_faster_path() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, true);
        sched.set_eligible(PathKind::Wifi, true);
        sched.note_rtt(PathKind::Wired, Duration::from_millis(1));
        sched.note_rtt(PathKind::Wifi, Duration::from_millis(10));

        assert_eq!(sched.pick(), Some(PathKind::Wired));
    }

    #[test]
    fn scheduler_skips_ineligible_path() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, false);
        sched.set_eligible(PathKind::Wifi, true);
        sched.note_rtt(PathKind::Wired, Duration::from_millis(1));
        sched.note_rtt(PathKind::Wifi, Duration::from_millis(10));

        assert_eq!(sched.pick(), Some(PathKind::Wifi));
    }

    #[test]
    fn scheduler_returns_none_when_no_paths() {
        let mut sched = Scheduler::new();
        assert_eq!(sched.pick(), None);
    }

    #[test]
    fn scheduler_prefers_unmeasured_over_slow() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, true);
        sched.set_eligible(PathKind::Wifi, true);
        // Wired unmeasured (defaults to 1ms), wifi slow
        sched.note_rtt(PathKind::Wifi, Duration::from_millis(50));

        assert_eq!(sched.pick(), Some(PathKind::Wired));
    }

    #[test]
    fn scheduler_penalizes_congested_path() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, true);
        sched.set_eligible(PathKind::Wifi, true);
        // Equal RTT, but wired is nearly out of send buffer
        sched.note_rtt(PathKind::Wired, Duration::from_millis(2));
        sched.note_rtt(PathKind::Wifi, Duration::from_millis(2));
        sched.note_queue_space(PathKind::Wired, 32 * 1024); // below LOW threshold
        sched.note_queue_space(PathKind::Wifi, 1024 * 1024);

        assert_eq!(sched.pick(), Some(PathKind::Wifi));
    }
}
