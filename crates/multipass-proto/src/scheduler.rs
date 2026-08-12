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

use crate::PathId;
use std::collections::HashMap;
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

/// Picks paths using smooth weighted round-robin over dynamically registered IDs.
pub struct Scheduler {
    paths: Vec<(PathId, PathState)>,
    indices: HashMap<PathId, usize>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            indices: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn insert(&mut self, path: PathId) -> bool {
        if self.indices.contains_key(&path) {
            return false;
        }
        let index = self.paths.len();
        self.paths.push((path, PathState::default()));
        self.indices.insert(path, index);
        true
    }

    pub fn remove(&mut self, path: PathId) -> bool {
        let Some(index) = self.indices.remove(&path) else {
            return false;
        };
        self.paths.remove(index);
        for (new_index, (id, _)) in self.paths[index..].iter().enumerate() {
            self.indices.insert(*id, index + new_index);
        }
        true
    }

    fn state_mut(&mut self, path: PathId) -> Option<&mut PathState> {
        let index = *self.indices.get(&path)?;
        Some(&mut self.paths[index].1)
    }

    /// Mark a path eligible (alive + ready) or not.
    pub fn set_eligible(&mut self, path: PathId, eligible: bool) {
        let Some(state) = self.state_mut(path) else {
            return;
        };
        if state.eligible != eligible {
            state.current_weight = 0.0;
        }
        state.eligible = eligible;
    }

    pub fn note_rtt(&mut self, path: PathId, rtt: Duration) {
        if let Some(state) = self.state_mut(path) {
            state.rtt = Some(rtt);
        }
    }

    pub fn note_path_stats(&mut self, path: PathId, rtt: Duration, cwnd: u64) {
        if let Some(state) = self.state_mut(path) {
            state.rtt = Some(rtt);
            state.cwnd = cwnd.max(1);
        }
    }

    pub fn note_queue_space(&mut self, path: PathId, bytes: usize) {
        if let Some(state) = self.state_mut(path) {
            state.queue_space = bytes;
        }
    }

    fn weight(state: &PathState) -> Option<f64> {
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

    pub fn pick(&mut self) -> Option<PathId> {
        let strongest = self
            .paths
            .iter()
            .filter_map(|(_, state)| Self::weight(state))
            .fold(0.0, f64::max);
        if strongest == 0.0 {
            return None;
        }

        let exploration_floor = strongest / 19.0;
        let total: f64 = self
            .paths
            .iter()
            .filter_map(|(_, state)| Self::weight(state))
            .map(|weight| weight.max(exploration_floor))
            .sum();

        let mut chosen = None;
        let mut best = f64::NEG_INFINITY;
        for (index, (_, state)) in self.paths.iter_mut().enumerate() {
            let Some(weight) = Self::weight(state) else {
                continue;
            };
            state.current_weight += weight.max(exploration_floor);
            if state.current_weight > best {
                best = state.current_weight;
                chosen = Some(index);
            }
        }

        let chosen = chosen.expect("positive total weight has an eligible path");
        self.paths[chosen].1.current_weight -= total;
        Some(self.paths[chosen].0)
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

    fn path(value: u16) -> PathId {
        PathId::new(value)
    }

    #[test]
    fn scheduler_returns_none_with_zero_paths() {
        assert_eq!(Scheduler::new().pick(), None);
    }

    #[test]
    fn scheduler_always_selects_the_only_eligible_path() {
        let mut scheduler = Scheduler::new();
        scheduler.insert(path(7));
        scheduler.set_eligible(path(7), true);

        for _ in 0..100 {
            assert_eq!(scheduler.pick(), Some(path(7)));
        }
    }

    #[test]
    fn scheduler_weights_two_paths_by_quic_cwnd_over_rtt() {
        let mut scheduler = Scheduler::new();
        scheduler.insert(path(1));
        scheduler.insert(path(2));
        scheduler.set_eligible(path(1), true);
        scheduler.set_eligible(path(2), true);
        scheduler.note_path_stats(path(1), Duration::from_millis(1), 64 * 1024);
        scheduler.note_path_stats(path(2), Duration::from_millis(2), 64 * 1024);

        let mut counts = [0; 2];
        for _ in 0..300 {
            counts[usize::from(scheduler.pick().unwrap().get() - 1)] += 1;
        }

        assert_eq!(counts, [200, 100]);
    }

    #[test]
    fn scheduler_selects_three_registered_paths() {
        let mut scheduler = Scheduler::new();
        for id in 1..=3 {
            scheduler.insert(path(id));
            scheduler.set_eligible(path(id), true);
            scheduler.note_path_stats(path(id), Duration::from_millis(1), 64 * 1024);
        }

        let mut counts = [0; 3];
        for _ in 0..300 {
            counts[usize::from(scheduler.pick().unwrap().get() - 1)] += 1;
        }

        assert_eq!(counts, [100, 100, 100]);
    }

    #[test]
    fn scheduler_removal_discards_path_state_without_disturbing_survivors() {
        let mut scheduler = Scheduler::new();
        for id in 1..=3 {
            scheduler.insert(path(id));
            scheduler.set_eligible(path(id), true);
        }
        assert!(scheduler.remove(path(2)));
        assert!(!scheduler.remove(path(2)));

        for _ in 0..100 {
            assert_ne!(scheduler.pick(), Some(path(2)));
        }
        assert_eq!(scheduler.len(), 2);
    }

    #[test]
    fn scheduler_rejects_duplicate_registration() {
        let mut scheduler = Scheduler::new();
        assert!(scheduler.insert(path(1)));
        assert!(!scheduler.insert(path(1)));
        assert_eq!(scheduler.len(), 1);
    }

    #[test]
    fn scheduler_skips_ineligible_paths() {
        let mut scheduler = Scheduler::new();
        scheduler.insert(path(1));
        scheduler.insert(path(2));
        scheduler.set_eligible(path(1), false);
        scheduler.set_eligible(path(2), true);

        assert_eq!(scheduler.pick(), Some(path(2)));
    }

    #[test]
    fn scheduler_preserves_exploration_share_for_low_cwnd_path() {
        let mut scheduler = Scheduler::new();
        scheduler.insert(path(1));
        scheduler.insert(path(2));
        scheduler.set_eligible(path(1), true);
        scheduler.set_eligible(path(2), true);
        scheduler.note_path_stats(path(1), Duration::from_millis(1), 4 * 1024 * 1024);
        scheduler.note_path_stats(path(2), Duration::from_millis(2), 16 * 1024);

        let mut slow = 0;
        for _ in 0..1_000 {
            if scheduler.pick() == Some(path(2)) {
                slow += 1;
            }
        }

        assert!(slow >= 50);
    }

    #[test]
    fn scheduler_penalizes_congested_path() {
        let mut scheduler = Scheduler::new();
        scheduler.insert(path(1));
        scheduler.insert(path(2));
        scheduler.set_eligible(path(1), true);
        scheduler.set_eligible(path(2), true);
        scheduler.note_rtt(path(1), Duration::from_millis(2));
        scheduler.note_rtt(path(2), Duration::from_millis(2));
        scheduler.note_queue_space(path(1), 32 * 1024);
        scheduler.note_queue_space(path(2), 1024 * 1024);

        assert_eq!(scheduler.pick(), Some(path(2)));
    }
}
