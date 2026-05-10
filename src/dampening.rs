//! BGP Route Dampening (RFC 2439)
//!
//! Tracks per-prefix flap history and suppresses unstable routes.
//!
//! Algorithm:
//!   - Each route withdrawal adds `penalty` (default 1000)
//!   - Penalty decays exponentially with `half_life` (default 15 min)
//!   - Routes with penalty > `suppress_limit` (default 2000) are suppressed
//!   - Routes are unsuppressed when penalty falls below `reuse_limit` (default 750)
//!   - Suppression cannot exceed `max_suppress_time` (default 60 min)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::rib::PrefixKey;

/// Per-prefix dampening state.
#[derive(Debug, Clone)]
pub struct PrefixDampening {
    /// Current accumulated penalty.
    pub penalty: f64,
    /// Whether this prefix is currently suppressed.
    pub suppressed: bool,
    /// When this prefix was last suppressed (to enforce max_suppress_time).
    pub suppressed_at: Option<Instant>,
    /// Last time penalty was decayed.
    pub last_decay: Instant,
    /// Number of times this prefix has been suppressed.
    pub suppress_count: u32,
}

impl PrefixDampening {
    fn new() -> Self {
        Self {
            penalty: 0.0,
            suppressed: false,
            suppressed_at: None,
            last_decay: Instant::now(),
            suppress_count: 0,
        }
    }

    /// Apply exponential decay based on elapsed time.
    ///
    /// decay_factor = 0.5 ^ (elapsed_secs / half_life_secs)
    fn decay(&mut self, half_life_secs: f64) {
        let elapsed = self.last_decay.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let decay_factor = 0.5_f64.powf(elapsed / half_life_secs);
            self.penalty *= decay_factor;
            self.last_decay = Instant::now();
        }
    }
}

/// Dampening configuration parameters.
#[derive(Debug, Clone)]
pub struct DampeningConfig {
    /// Penalty added on each route withdrawal (flap).
    pub penalty_per_flap: f64,
    /// Penalty threshold above which routes are suppressed.
    pub suppress_limit: f64,
    /// Penalty threshold below which suppressed routes are re-enabled.
    pub reuse_limit: f64,
    /// Half-life for penalty decay (seconds).
    pub half_life_secs: f64,
    /// Maximum time a route can be suppressed.
    pub max_suppress_time: Duration,
}

impl Default for DampeningConfig {
    fn default() -> Self {
        Self {
            penalty_per_flap: 1000.0,
            suppress_limit: 2000.0,
            reuse_limit: 750.0,
            half_life_secs: 900.0, // 15 minutes
            max_suppress_time: Duration::from_secs(3600), // 60 minutes
        }
    }
}

/// Route dampening engine: tracks all prefix penalties.
#[derive(Debug, Default)]
pub struct DampeningTable {
    /// Per-peer, per-prefix dampening state.
    state: HashMap<(SocketAddr, PrefixKey), PrefixDampening>,
    pub config: DampeningConfig,
}

impl DampeningTable {
    pub fn new(config: DampeningConfig) -> Self {
        Self {
            state: HashMap::new(),
            config,
        }
    }

    /// Record a route withdrawal (flap) for a prefix.
    ///
    /// Returns `true` if the route should now be suppressed.
    pub fn record_withdrawal(&mut self, peer: SocketAddr, prefix: &PrefixKey) -> bool {
        let cfg = &self.config;
        let entry = self
            .state
            .entry((peer, prefix.clone()))
            .or_insert_with(PrefixDampening::new);

        entry.decay(cfg.half_life_secs);
        entry.penalty += cfg.penalty_per_flap;

        if !entry.suppressed && entry.penalty >= cfg.suppress_limit {
            entry.suppressed = true;
            entry.suppressed_at = Some(Instant::now());
            entry.suppress_count += 1;
            return true;
        }
        entry.suppressed
    }

    /// Check dampening state for a prefix after receiving a new advertisement.
    ///
    /// Returns `true` if the route remains suppressed (should not be installed).
    pub fn check_advertisement(&mut self, peer: SocketAddr, prefix: &PrefixKey) -> bool {
        let cfg = &self.config;
        let entry = match self.state.get_mut(&(peer, prefix.clone())) {
            Some(e) => e,
            None => return false,
        };

        entry.decay(cfg.half_life_secs);

        // Check max suppress time
        if let Some(suppressed_at) = entry.suppressed_at {
            if suppressed_at.elapsed() >= cfg.max_suppress_time {
                entry.suppressed = false;
                entry.suppressed_at = None;
                return false;
            }
        }

        // Check reuse threshold
        if entry.suppressed && entry.penalty < cfg.reuse_limit {
            entry.suppressed = false;
            entry.suppressed_at = None;
        }

        entry.suppressed
    }

    /// Get the current penalty for a prefix (after applying decay).
    pub fn current_penalty(&mut self, peer: SocketAddr, prefix: &PrefixKey) -> f64 {
        let half_life = self.config.half_life_secs;
        let entry = self
            .state
            .entry((peer, prefix.clone()))
            .or_insert_with(PrefixDampening::new);
        entry.decay(half_life);
        entry.penalty
    }

    /// Whether a prefix is currently suppressed.
    pub fn is_suppressed(&self, peer: SocketAddr, prefix: &PrefixKey) -> bool {
        self.state
            .get(&(peer, prefix.clone()))
            .map(|e| e.suppressed)
            .unwrap_or(false)
    }

    /// Number of suppressed prefixes.
    pub fn suppressed_count(&self) -> usize {
        self.state.values().filter(|e| e.suppressed).count()
    }

    /// Remove all dampening state for a peer (on peer removal).
    pub fn remove_peer(&mut self, peer: SocketAddr) {
        self.state.retain(|(p, _), _| *p != peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn pfx(a: u8) -> PrefixKey {
        PrefixKey {
            address: Ipv4Addr::new(10, 0, 0, a),
            prefix_len: 24,
        }
    }

    fn peer() -> SocketAddr {
        "10.0.0.1:179".parse().unwrap()
    }

    #[test]
    fn test_no_suppression_single_flap() {
        let mut table = DampeningTable::new(DampeningConfig::default());
        // One flap: penalty = 1000, suppress_limit = 2000 → not suppressed
        let suppressed = table.record_withdrawal(peer(), &pfx(1));
        assert!(!suppressed);
    }

    #[test]
    fn test_suppression_after_two_flaps() {
        // suppress_limit = 1500 → 2 flaps (2×1000 ≈ 2000) always exceeds it
        let mut table = DampeningTable::new(DampeningConfig {
            suppress_limit: 1500.0,
            ..Default::default()
        });
        table.record_withdrawal(peer(), &pfx(1));
        let suppressed = table.record_withdrawal(peer(), &pfx(1));
        assert!(suppressed);
        assert!(table.is_suppressed(peer(), &pfx(1)));
        assert_eq!(table.suppressed_count(), 1);
    }

    #[test]
    fn test_unsuppressed_on_advertisement_below_reuse() {
        let mut table = DampeningTable::new(DampeningConfig {
            suppress_limit: 1500.0,
            reuse_limit: 750.0,
            ..Default::default()
        });
        // Suppress the route
        table.record_withdrawal(peer(), &pfx(1));
        table.record_withdrawal(peer(), &pfx(1));
        assert!(table.is_suppressed(peer(), &pfx(1)));

        // Force penalty below reuse threshold
        let entry = table.state.get_mut(&(peer(), pfx(1))).unwrap();
        entry.penalty = 500.0;

        // Advertisement check: penalty < reuse_limit → unsuppressed
        let still_suppressed = table.check_advertisement(peer(), &pfx(1));
        assert!(!still_suppressed);
        assert!(!table.is_suppressed(peer(), &pfx(1)));
    }

    #[test]
    fn test_max_suppress_time_override() {
        let mut table = DampeningTable::new(DampeningConfig {
            suppress_limit: 1500.0,
            max_suppress_time: Duration::from_millis(1),
            ..Default::default()
        });
        table.record_withdrawal(peer(), &pfx(1));
        table.record_withdrawal(peer(), &pfx(1));
        assert!(table.is_suppressed(peer(), &pfx(1)));

        // Wait past max suppress time
        std::thread::sleep(Duration::from_millis(5));
        let still_suppressed = table.check_advertisement(peer(), &pfx(1));
        assert!(!still_suppressed);
    }

    #[test]
    fn test_penalty_decays_over_time() {
        let mut table = DampeningTable::new(DampeningConfig {
            half_life_secs: 1.0, // 1 second half-life for fast test
            ..Default::default()
        });
        let entry = table
            .state
            .entry((peer(), pfx(1)))
            .or_insert_with(PrefixDampening::new);
        entry.penalty = 2000.0;

        std::thread::sleep(Duration::from_millis(1100)); // ~1 half-life
        let penalty = table.current_penalty(peer(), &pfx(1));
        // After 1 half-life, penalty should be ~1000 (±10% for timing jitter)
        assert!(penalty < 1100.0, "penalty={penalty} should be < 1100 after 1 half-life");
        assert!(penalty > 800.0, "penalty={penalty} should be > 800 after 1 half-life");
    }

    #[test]
    fn test_remove_peer_clears_state() {
        let mut table = DampeningTable::new(DampeningConfig {
            suppress_limit: 1500.0,
            ..Default::default()
        });
        table.record_withdrawal(peer(), &pfx(1));
        table.record_withdrawal(peer(), &pfx(1));
        assert_eq!(table.suppressed_count(), 1);

        table.remove_peer(peer());
        assert_eq!(table.suppressed_count(), 0);
        assert_eq!(table.state.len(), 0);
    }

    #[test]
    fn test_independent_prefixes() {
        let mut table = DampeningTable::new(DampeningConfig {
            suppress_limit: 1500.0,
            ..Default::default()
        });
        // p1 gets suppressed (2 flaps × 1000 = 2000 > 1500), p2 does not (1 flap = 1000 < 1500)
        table.record_withdrawal(peer(), &pfx(1));
        table.record_withdrawal(peer(), &pfx(1));
        table.record_withdrawal(peer(), &pfx(2));

        assert!(table.is_suppressed(peer(), &pfx(1)));
        assert!(!table.is_suppressed(peer(), &pfx(2)));
        assert_eq!(table.suppressed_count(), 1);
    }
}
