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

/// Per-path scheduling inputs, updated from QUIC path statistics.
#[derive(Debug, Clone, Copy)]
struct PathState {
    /// Last measured round-trip time.
    rtt: Option<Duration>,
    /// Whether the path is alive and ready for data.
    eligible: bool,
    /// Current QUIC congestion window in bytes.
    cwnd: u64,
    /// Last observed datagram send buffer space in bytes.
    queue_space: usize,
    /// Smooth weighted-round-robin accumulator.
    current_weight: f64,
}

impl Default for PathState {
    fn default() -> Self {
        Self {
            rtt: None,
            eligible: false,
            cwnd: 64 * 1024,
            queue_space: usize::MAX,
            current_weight: 0.0,
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
        let state = &mut self.paths[idx(path)];
        if state.eligible != eligible {
            state.current_weight = 0.0;
        }
        state.eligible = eligible;
    }

    /// Record a measured RTT for a path while preserving its current
    /// congestion-window estimate.
    pub fn note_rtt(&mut self, path: PathKind, rtt: Duration) {
        self.paths[idx(path)].rtt = Some(rtt);
    }

    /// Record QUIC path capacity inputs. `cwnd / RTT` estimates the path's
    /// current service rate; smooth weighted round-robin then stripes packets
    /// in proportion to that estimate without starving slower healthy paths.
    pub fn note_path_stats(&mut self, path: PathKind, rtt: Duration, cwnd: u64) {
        let state = &mut self.paths[idx(path)];
        state.rtt = Some(rtt);
        state.cwnd = cwnd.max(1);
    }

    /// Record the current datagram send buffer space for a path.
    pub fn note_queue_space(&mut self, path: PathKind, bytes: usize) {
        self.paths[idx(path)].queue_space = bytes;
    }

    /// Effective path service-rate weight. Returns `None` if the path is not
    /// eligible. Queue pressure reduces, but never eliminates, the weight of a
    /// live path; only liveness/handshake state can make a path ineligible.
    fn weight(&self, path: PathKind) -> Option<f64> {
        let state = &self.paths[idx(path)];
        if !state.eligible {
            return None;
        }

        let rtt = state.rtt.unwrap_or(Duration::from_millis(1));
        let service_rate = state.cwnd as f64 / rtt.as_secs_f64().max(0.000_001);

        const FULL: f64 = 1024.0 * 1024.0;
        const LOW: f64 = 64.0 * 1024.0;
        let free = state.queue_space as f64;
        let queue_factor = if free >= FULL {
            1.0
        } else if free <= LOW {
            0.05
        } else {
            0.05 + 0.95 * ((free - LOW) / (FULL - LOW))
        };
        Some((service_rate * queue_factor).max(1.0))
    }

    /// Pick a path using smooth weighted round-robin. Each eligible path's
    /// accumulator grows by its current capacity estimate; the largest wins
    /// and pays the total weight. Over a batch this yields the capacity ratio
    /// while retaining deterministic, per-packet decisions.
    pub fn pick(&mut self) -> Option<PathKind> {
        let mut weights = [self.weight(PathKind::Wired), self.weight(PathKind::Wifi)];
        let strongest = weights.iter().flatten().copied().fold(0.0, f64::max);
        if strongest == 0.0 {
            return None;
        }

        // A path that receives no traffic cannot grow its congestion window,
        // so a pure cwnd/RTT weight creates a positive-feedback starvation
        // loop. Give every eligible path at least 5% of picks against the
        // strongest path: floor / (strongest + floor) = 1 / 20.
        let exploration_floor = strongest / 19.0;
        for weight in weights.iter_mut().flatten() {
            *weight = weight.max(exploration_floor);
        }

        let total: f64 = weights.iter().flatten().sum();
        let mut chosen = None;
        let mut best = f64::NEG_INFINITY;
        for (index, weight) in weights.into_iter().enumerate() {
            let Some(weight) = weight else { continue };
            self.paths[index].current_weight += weight;
            if self.paths[index].current_weight > best {
                best = self.paths[index].current_weight;
                chosen = Some(index);
            }
        }

        let chosen = chosen.expect("positive total weight has an eligible path");
        self.paths[chosen].current_weight -= total;
        Some(if chosen == 0 {
            PathKind::Wired
        } else {
            PathKind::Wifi
        })
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
    fn scheduler_does_not_starve_slower_eligible_path() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, true);
        sched.set_eligible(PathKind::Wifi, true);
        sched.note_rtt(PathKind::Wired, Duration::from_millis(1));
        sched.note_rtt(PathKind::Wifi, Duration::from_millis(10));

        let mut wired = 0;
        let mut wifi = 0;
        for _ in 0..100 {
            match sched.pick().unwrap() {
                PathKind::Wired => wired += 1,
                PathKind::Wifi => wifi += 1,
            }
        }

        assert!(wired > wifi, "faster path should receive the larger share");
        assert!(
            wifi > 0,
            "every eligible uncongested path must carry traffic"
        );
    }

    #[test]
    fn scheduler_weights_by_quic_cwnd_over_rtt() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, true);
        sched.set_eligible(PathKind::Wifi, true);
        sched.note_path_stats(PathKind::Wired, Duration::from_millis(1), 64 * 1024);
        sched.note_path_stats(PathKind::Wifi, Duration::from_millis(2), 64 * 1024);

        let mut wired = 0;
        let mut wifi = 0;
        for _ in 0..300 {
            match sched.pick().unwrap() {
                PathKind::Wired => wired += 1,
                PathKind::Wifi => wifi += 1,
            }
        }

        assert_eq!((wired, wifi), (200, 100));
    }

    #[test]
    fn scheduler_preserves_exploration_share_for_low_cwnd_path() {
        let mut sched = Scheduler::new();
        sched.set_eligible(PathKind::Wired, true);
        sched.set_eligible(PathKind::Wifi, true);
        sched.note_path_stats(PathKind::Wired, Duration::from_millis(1), 4 * 1024 * 1024);
        sched.note_path_stats(PathKind::Wifi, Duration::from_millis(2), 16 * 1024);

        let mut wifi = 0;
        for _ in 0..1_000 {
            if sched.pick() == Some(PathKind::Wifi) {
                wifi += 1;
            }
        }

        assert!(
            wifi >= 50,
            "an eligible path needs at least a 5% exploration share to grow its congestion window"
        );
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
