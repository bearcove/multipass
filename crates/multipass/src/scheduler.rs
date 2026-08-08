//! Weighted load-balancing scheduler for the two transport paths.
//!
//! The transport sends each packet on ONE path — aggregate delivery, not the
//! plain "send on both" duplication. This [`Scheduler`] picks which path via
//! deficit-WRR, with weights derived from live path health (measured RTT and
//! receive liveness). When a path's RTT spikes or its acks stall, its weight
//! is shifted onto the survivor so failover stays seamless. The receiver still
//! dedups by sequence number (see [`multipass_proto::Dedup`]); the aggregate
//! send just doesn't eagerly duplicate every packet.
//!
//! The scheduler is deliberately a standalone, tunable component: build it
//! with a [`SchedulerConfig`], feed it health observations, and ask it which
//! path to use next.

use std::time::{Duration, Instant};

use crate::PathKind;

/// Tunable knobs for the scheduler.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// Weight for a path with no RTT measurement yet (or equal to the others).
    pub base_weight: u32,
    /// Floor for a healthy-but-slower path. Keeps it carrying a little load so
    /// it stays warm and can take over instantly during a failover.
    pub min_weight: u32,
    /// Ceiling for the fastest path.
    pub max_weight: u32,
    /// No datagram received in this long -> the path is treated as stalled and
    /// its weight drops to [`Self::stall_weight`].
    pub stall_after: Duration,
    /// Weight applied while a path is stalled.
    pub stall_weight: u32,
    /// Deficit-WRR credit granted per service round per unit of weight.
    pub quantum: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            base_weight: 100,
            min_weight: 10,
            max_weight: 1000,
            stall_after: Duration::from_secs(1),
            stall_weight: 5,
            quantum: 1,
        }
    }
}

/// One path's scheduler-side health snapshot.
#[derive(Debug, Clone, Copy)]
pub struct PathHealth {
    /// Current WRR weight (0 = dead / not eligible).
    pub weight: u32,
    /// Last measured round-trip time, if any.
    pub rtt: Option<Duration>,
    /// When the last datagram was received on this path.
    pub last_recv: Option<Instant>,
    /// Whether the path is alive (reader task running).
    pub alive: bool,
}

/// Deficit-WRR scheduler over the two paths.
///
/// Internally: each path holds a credit balance. Picking a path decrements its
/// credit by one; when no path has credit left, a service round grants every
/// eligible path `quantum * weight` more. The result is that path `i` carries a
/// share of packets proportional to `weight[i] / sum(weights)`, with the
/// fastest, most alive path weighted highest.
pub struct Scheduler {
    cfg: SchedulerConfig,
    health: [PathHealth; 2],
    credits: [i64; 2],
}

impl Scheduler {
    /// Build a scheduler with the given configuration. Both paths start with
    /// `base_weight` and are assumed alive.
    pub fn new(cfg: SchedulerConfig) -> Self {
        let w = cfg.base_weight;
        Self {
            cfg,
            health: [
                PathHealth { weight: w, rtt: None, last_recv: None, alive: true },
                PathHealth { weight: w, rtt: None, last_recv: None, alive: true },
            ],
            credits: [0, 0],
        }
    }

    /// The path to send the next packet on.
    pub fn pick(&mut self) -> PathKind {
        loop {
            let mut best = None;
            let mut best_credit = i64::MIN;
            for i in PathKind::ALL {
                if self.health[idx(i)].weight == 0 {
                    continue; // dead / not eligible
                }
                if self.credits[idx(i)] > best_credit {
                    best = Some(i);
                    best_credit = self.credits[idx(i)];
                }
            }
            let Some(i) = best else {
                // No eligible path; caller skips (nothing alive).
                return PathKind::Wired;
            };
            if best_credit >= 0 {
                self.credits[idx(i)] -= 1;
                return i;
            }
            self.service();
        }
    }

    /// Record a measured RTT for a path and recompute weights.
    pub fn note_rtt(&mut self, path: PathKind, rtt: Duration) {
        self.health[idx(path)].rtt = Some(rtt);
        self.recompute();
    }

    /// Note that a datagram was received on a path (liveness) and recompute.
    pub fn note_recv(&mut self, path: PathKind) {
        self.health[idx(path)].last_recv = Some(Instant::now());
        self.recompute();
    }

    /// Mark a path alive or dead. Dead paths get weight 0 (all traffic re-homes
    /// to the survivor); re-aliving restores a base weight.
    pub fn set_alive(&mut self, path: PathKind, alive: bool) {
        self.health[idx(path)].alive = alive;
        self.recompute();
    }

    /// Explicitly override a path's weight (operator tuning / manual re-home).
    /// The next health observation recomputes it back from live data.
    pub fn set_weight(&mut self, path: PathKind, weight: u32) {
        self.health[idx(path)].weight = weight;
    }

    /// Re-evaluate stall/death state from the clock. Call periodically (the
    /// transport's probe loop does) so a path that stops delivering sheds its
    /// weight even though no new packets arrive to trigger a recompute.
    pub fn tick(&mut self) {
        self.recompute();
    }

    /// Current health of both paths, in Wired/Wifi order.
    pub fn health(&self) -> [PathHealth; 2] {
        self.health
    }

    /// The configuration this scheduler was built with.
    pub fn config(&self) -> SchedulerConfig {
        self.cfg
    }

    /// Service round: grant every eligible path credit proportional to weight.
    fn service(&mut self) {
        for i in PathKind::ALL {
            let w = self.health[idx(i)].weight as i64;
            if w > 0 {
                self.credits[idx(i)] = self
                    .credits
                    .get_mut(idx(i))
                    .unwrap()
                    .saturating_add(self.cfg.quantum as i64 * w);
            }
        }
    }

    /// Recompute each path's weight from alive / stall / RTT health.
    fn recompute(&mut self) {
        let now = Instant::now();
        // Reference RTT = the minimum among alive, non-stalled, measured paths.
        let mut ref_rtt: Option<Duration> = None;
        for h in &self.health {
            if h.alive && !Self::stalled(&self.cfg, h, now) {
                if let Some(r) = h.rtt {
                    ref_rtt = Some(match ref_rtt {
                        Some(cur) if cur <= r => cur,
                        _ => r,
                    });
                }
            }
        }
        for i in PathKind::ALL {
            let h = self.health[idx(i)];
            let w = if !h.alive {
                0
            } else if Self::stalled(&self.cfg, &h, now) {
                self.cfg.stall_weight
            } else {
                match (h.rtt, ref_rtt) {
                    (Some(r), Some(refr)) => {
                        // ratio <= 1 for the slower path, >= 1 for the faster.
                        let ratio = refr.as_secs_f64() / r.as_secs_f64();
                        let w = (self.cfg.base_weight as f64 * ratio).round() as u32;
                        w.clamp(self.cfg.min_weight, self.cfg.max_weight)
                    }
                    _ => self.cfg.base_weight,
                }
            };
            self.health[idx(i)].weight = w;
        }
    }

    fn stalled(cfg: &SchedulerConfig, h: &PathHealth, now: Instant) -> bool {
        match h.last_recv {
            Some(t) => now.duration_since(t) > cfg.stall_after,
            None => false,
        }
    }
}

fn idx(p: PathKind) -> usize {
    match p {
        PathKind::Wired => 0,
        PathKind::Wifi => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both_have_traffic(s: &mut Scheduler, n: usize) -> (u32, u32) {
        let (mut a, mut b) = (0u32, 0u32);
        for _ in 0..n {
            match s.pick() {
                PathKind::Wired => a += 1,
                PathKind::Wifi => b += 1,
            }
        }
        (a, b)
    }

    #[test]
    fn equal_weights_alternate() {
        let mut s = Scheduler::new(SchedulerConfig::default());
        let (wired, wifi) = both_have_traffic(&mut s, 100);
        assert!(wired > 0 && wifi > 0, "equal weights must spread load");
        assert!((wired as i64 - wifi as i64).abs() <= 1, "alternating evenly");
    }

    #[test]
    fn dead_path_rehomes_all_traffic() {
        let mut s = Scheduler::new(SchedulerConfig::default());
        s.set_alive(PathKind::Wired, false);
        let (wired, wifi) = both_have_traffic(&mut s, 100);
        assert_eq!(wired, 0, "dead path gets no traffic");
        assert_eq!(wifi, 100, "survivor carries everything");
    }

    #[test]
    fn slower_path_gets_less_weight() {
        let cfg = SchedulerConfig::default();
        let mut s = Scheduler::new(cfg);
        // Fast path: 1ms. Slow path: 10ms. Weight ratio ~10:1.
        s.note_rtt(PathKind::Wired, Duration::from_millis(1));
        s.note_rtt(PathKind::Wifi, Duration::from_millis(10));
        let (wired, wifi) = both_have_traffic(&mut s, 1000);
        assert!(wired > wifi, "faster path should carry more");
        assert!(wifi > 0, "slower path still carries a little (warm standby)");
    }

    #[test]
    fn stalled_path_sheds_weight() {
        let cfg = SchedulerConfig {
            stall_after: Duration::from_millis(1),
            stall_weight: 5,
            ..Default::default()
        };
        let mut s = Scheduler::new(cfg);
        s.note_recv(PathKind::Wired); // then let it go stale
        std::thread::sleep(Duration::from_millis(5));
        s.tick(); // re-evaluate stall from the clock
        let health = s.health();
        assert_eq!(health[idx(PathKind::Wired)].weight, cfg.stall_weight);
        assert_eq!(health[idx(PathKind::Wifi)].weight, cfg.base_weight);
    }
}