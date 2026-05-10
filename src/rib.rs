use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use crate::attr::PathAttributes;
use crate::dampening::{DampeningConfig, DampeningTable};
use crate::message::update::Prefix;
use crate::rpki::{RovState, RpkiValidator};

/// A route entry stored in the RIB.
#[derive(Debug, Clone)]
pub struct Route {
    /// The network prefix for this route.
    #[allow(dead_code)]
    pub prefix: Prefix,
    /// BGP path attributes associated with this route.
    pub attrs: PathAttributes,
    /// The peer that advertised this route.
    pub peer_addr: SocketAddr,
    /// The peer's AS number.
    pub peer_as: u32,
    /// When this route was received (monotonic).
    pub received_at: std::time::Instant,
    /// RFC 4724: route is stale pending graceful restart.
    pub stale: bool,
    /// RFC 6811: RPKI/ROA validation state.
    pub rov_state: RovState,
}

impl Route {
    pub fn new(prefix: Prefix, attrs: PathAttributes, peer_addr: SocketAddr, peer_as: u32) -> Self {
        Self {
            prefix,
            attrs,
            peer_addr,
            peer_as,
            received_at: std::time::Instant::now(),
            stale: false,
            rov_state: RovState::NotFound,
        }
    }
}

/// Key used to look up routes: the network prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrefixKey {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

impl From<&Prefix> for PrefixKey {
    fn from(p: &Prefix) -> Self {
        PrefixKey {
            address: p.address,
            prefix_len: p.prefix_len,
        }
    }
}

impl std::fmt::Display for PrefixKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// Adj-RIB-In: routes received from a specific peer.
/// Key: prefix → route received from that peer.
pub type AdjRibIn = HashMap<PrefixKey, Route>;

/// Loc-RIB: the best route for each prefix after the decision process.
pub type LocRib = HashMap<PrefixKey, Route>;

/// Adj-RIB-Out: routes we will advertise to each peer.
pub type AdjRibOut = HashMap<PrefixKey, Route>;

/// The full BGP Routing Information Base.
///
/// Thread-safe via Arc<RwLock<...>> so it can be shared across peer tasks.
pub struct Rib {
    /// Adj-RIB-In per peer.
    adj_rib_in: HashMap<SocketAddr, AdjRibIn>,
    /// The best route for each prefix (Loc-RIB).
    loc_rib: LocRib,
    /// Adj-RIB-Out per peer (routes to advertise).
    #[allow(dead_code)]
    adj_rib_out: HashMap<SocketAddr, AdjRibOut>,
    /// RFC 2439 route dampening engine.
    pub dampening: DampeningTable,
    /// RFC 6811 RPKI/ROA validator.
    pub rpki: RpkiValidator,
}

impl Default for Rib {
    fn default() -> Self {
        Self {
            adj_rib_in: HashMap::new(),
            loc_rib: HashMap::new(),
            adj_rib_out: HashMap::new(),
            dampening: DampeningTable::new(DampeningConfig::default()),
            rpki: RpkiValidator::default(),
        }
    }
}

impl Rib {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in Arc<RwLock> for shared ownership.
    pub fn shared() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self::new()))
    }

    /// Process received routes from a peer: update Adj-RIB-In and run decision process.
    pub fn process_update(
        &mut self,
        peer_addr: SocketAddr,
        peer_as: u32,
        nlri: &[Prefix],
        attrs: &PathAttributes,
        withdrawn: &[Prefix],
    ) {
        // Record withdrawals in the dampening table
        for prefix in withdrawn {
            let key = PrefixKey::from(prefix);
            self.dampening.record_withdrawal(peer_addr, &key);
        }

        let adj_in = self.adj_rib_in.entry(peer_addr).or_default();

        // Add/update new routes (skip suppressed or RPKI-strict-invalid ones)
        let mut affected_nlri: Vec<PrefixKey> = Vec::new();
        for prefix in nlri {
            let key = PrefixKey::from(prefix);
            let suppressed = self.dampening.check_advertisement(peer_addr, &key);

            // RPKI validation
            let rov = self
                .rpki
                .validate(prefix.address, prefix.prefix_len, peer_as);
            if suppressed || self.rpki.should_reject(rov) {
                continue;
            }

            let mut route = Route::new(prefix.clone(), attrs.clone(), peer_addr, peer_as);
            route.rov_state = rov;
            adj_in.insert(key.clone(), route);
            affected_nlri.push(key);
        }

        // Remove withdrawn routes
        for prefix in withdrawn {
            adj_in.remove(&PrefixKey::from(prefix));
        }

        // Re-run decision process for affected prefixes
        let affected: Vec<PrefixKey> = affected_nlri
            .into_iter()
            .chain(withdrawn.iter().map(PrefixKey::from))
            .collect();
        for key in affected {
            self.run_decision_process(&key);
        }
    }

    /// BGP decision process: select the best route for a prefix.
    ///
    /// Implements RFC 4271 §9.1 tie-breaking:
    /// 1. Highest LOCAL_PREF
    /// 2. Shortest AS_PATH length
    /// 3. Lowest ORIGIN (IGP < EGP < Incomplete)
    /// 4. Lowest MED
    /// 5. Prefer eBGP over iBGP (not applicable here without full peer info)
    /// 6. Oldest route (lowest received_at) as final tiebreaker
    fn run_decision_process(&mut self, key: &PrefixKey) {
        let mut candidates: Vec<&Route> = self
            .adj_rib_in
            .values()
            .filter_map(|rib| rib.get(key))
            .collect();

        if candidates.is_empty() {
            self.loc_rib.remove(key);
            return;
        }

        // Sort by preference (lower sort key = better)
        candidates.sort_by(|a, b| {
            let a_lp = a.attrs.local_pref.unwrap_or(100);
            let b_lp = b.attrs.local_pref.unwrap_or(100);
            // 1. Highest LOCAL_PREF wins
            b_lp.cmp(&a_lp)
                // 2. Shortest AS_PATH
                .then(a.attrs.as_path_len().cmp(&b.attrs.as_path_len()))
                // 3. Lowest ORIGIN
                .then_with(|| {
                    let a_origin = a.attrs.origin.map(|o| o as u8).unwrap_or(2);
                    let b_origin = b.attrs.origin.map(|o| o as u8).unwrap_or(2);
                    a_origin.cmp(&b_origin)
                })
                // 4. Lowest MED
                .then(
                    a.attrs
                        .multi_exit_disc
                        .unwrap_or(0)
                        .cmp(&b.attrs.multi_exit_disc.unwrap_or(0)),
                )
                // 5. Oldest route
                .then(a.received_at.cmp(&b.received_at))
        });

        let best = candidates[0].clone();
        self.loc_rib.insert(key.clone(), best);
    }

    /// Remove all routes from a disconnected peer.
    pub fn remove_peer(&mut self, peer_addr: SocketAddr) -> Vec<PrefixKey> {
        let removed_keys: Vec<PrefixKey> = self
            .adj_rib_in
            .remove(&peer_addr)
            .map(|rib| rib.into_keys().collect())
            .unwrap_or_default();

        for key in &removed_keys {
            self.run_decision_process(key);
        }
        self.dampening.remove_peer(peer_addr);
        removed_keys
    }

    /// RFC 4724: mark all routes from a peer as stale (peer disconnected, may restart).
    pub fn mark_peer_stale(&mut self, peer_addr: SocketAddr) {
        if let Some(rib) = self.adj_rib_in.get_mut(&peer_addr) {
            for route in rib.values_mut() {
                route.stale = true;
            }
        }
    }

    /// RFC 4724: remove all remaining stale routes for a peer (restart timer expired).
    pub fn remove_stale_for_peer(&mut self, peer_addr: SocketAddr) -> Vec<PrefixKey> {
        let stale_keys: Vec<PrefixKey> = self
            .adj_rib_in
            .get(&peer_addr)
            .map(|rib| {
                rib.iter()
                    .filter(|(_, r)| r.stale)
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();

        if let Some(rib) = self.adj_rib_in.get_mut(&peer_addr) {
            for key in &stale_keys {
                rib.remove(key);
            }
            if rib.is_empty() {
                self.adj_rib_in.remove(&peer_addr);
            }
        }

        for key in &stale_keys {
            self.run_decision_process(key);
        }
        stale_keys
    }

    /// Return the count of stale routes in Adj-RIB-In across all peers.
    pub fn stale_route_count(&self) -> usize {
        self.adj_rib_in
            .values()
            .flat_map(|rib| rib.values())
            .filter(|r| r.stale)
            .count()
    }

    /// Get the Loc-RIB (best routes).
    pub fn loc_rib(&self) -> &LocRib {
        &self.loc_rib
    }

    /// Get all routes from Adj-RIB-In for a peer.
    #[allow(dead_code)]
    pub fn adj_rib_in(&self, peer_addr: &SocketAddr) -> Option<&AdjRibIn> {
        self.adj_rib_in.get(peer_addr)
    }

    /// Number of prefixes in the Loc-RIB.
    #[allow(dead_code)]
    pub fn prefix_count(&self) -> usize {
        self.loc_rib.len()
    }

    /// Longest Prefix Match: find the most specific Loc-RIB entry covering `addr`.
    ///
    /// Returns `None` if no route covers the address.
    pub fn longest_match(&self, addr: Ipv4Addr) -> Option<(&PrefixKey, &Route)> {
        let addr_bits = u32::from(addr);
        self.loc_rib
            .iter()
            .filter(|(key, _)| {
                if key.prefix_len == 0 {
                    return true; // default route covers everything
                }
                let shift = 32 - key.prefix_len as u32;
                (addr_bits >> shift) == (u32::from(key.address) >> shift)
            })
            .max_by_key(|(key, _)| key.prefix_len)
    }

    /// Summary: (peer_count, total_adj_rib_in_routes, loc_rib_routes)
    pub fn summary(&self) -> (usize, usize, usize) {
        let total_adj: usize = self.adj_rib_in.values().map(|r| r.len()).sum();
        (self.adj_rib_in.len(), total_adj, self.loc_rib.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AsPathSegment, Origin};

    fn peer(n: u8) -> SocketAddr {
        format!("10.0.0.{}:179", n).parse().unwrap()
    }

    #[test]
    fn test_basic_route_insertion() {
        let mut rib = Rib::new();
        let prefix = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let attrs = PathAttributes {
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        };

        rib.process_update(peer(1), 65001, &[prefix.clone()], &attrs, &[]);
        assert_eq!(rib.prefix_count(), 1);
        let best = rib.loc_rib().get(&PrefixKey::from(&prefix)).unwrap();
        assert_eq!(best.peer_addr, peer(1));
    }

    #[test]
    fn test_best_path_local_pref() {
        let mut rib = Rib::new();
        let prefix = Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 24);

        let attrs_low = PathAttributes {
            local_pref: Some(50),
            ..Default::default()
        };
        rib.process_update(peer(1), 65001, &[prefix.clone()], &attrs_low, &[]);

        let attrs_high = PathAttributes {
            local_pref: Some(200),
            ..Default::default()
        };
        rib.process_update(peer(2), 65002, &[prefix.clone()], &attrs_high, &[]);

        let best = rib.loc_rib().get(&PrefixKey::from(&prefix)).unwrap();
        assert_eq!(best.peer_addr, peer(2), "Higher LOCAL_PREF should win");
    }

    #[test]
    fn test_best_path_as_path_length() {
        let mut rib = Rib::new();
        let prefix = Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);

        let attrs_long = PathAttributes {
            local_pref: Some(100),
            as_path: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
            ..Default::default()
        };
        rib.process_update(peer(1), 65001, &[prefix.clone()], &attrs_long, &[]);

        let attrs_short = PathAttributes {
            local_pref: Some(100),
            as_path: vec![AsPathSegment::AsSequence(vec![65004])],
            ..Default::default()
        };
        rib.process_update(peer(2), 65002, &[prefix.clone()], &attrs_short, &[]);

        let best = rib.loc_rib().get(&PrefixKey::from(&prefix)).unwrap();
        assert_eq!(best.peer_addr, peer(2), "Shorter AS_PATH should win");
    }

    #[test]
    fn test_withdraw_route() {
        let mut rib = Rib::new();
        let prefix = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let attrs = PathAttributes::default();

        rib.process_update(peer(1), 65001, &[prefix.clone()], &attrs, &[]);
        assert_eq!(rib.prefix_count(), 1);

        rib.process_update(peer(1), 65001, &[], &attrs, &[prefix.clone()]);
        assert_eq!(rib.prefix_count(), 0);
    }

    #[test]
    fn test_remove_peer() {
        let mut rib = Rib::new();
        let p1 = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let p2 = Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let attrs = PathAttributes::default();

        rib.process_update(peer(1), 65001, &[p1.clone(), p2.clone()], &attrs, &[]);
        assert_eq!(rib.prefix_count(), 2);

        rib.remove_peer(peer(1));
        assert_eq!(rib.prefix_count(), 0);
    }

    #[test]
    fn test_summary() {
        let mut rib = Rib::new();
        let p1 = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let p2 = Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let attrs = PathAttributes::default();
        rib.process_update(peer(1), 65001, &[p1, p2], &attrs, &[]);
        let (peers, adj, loc) = rib.summary();
        assert_eq!(peers, 1);
        assert_eq!(adj, 2);
        assert_eq!(loc, 2);
    }

    #[test]
    fn test_longest_prefix_match_basic() {
        let mut rib = Rib::new();
        let attrs = PathAttributes::default();
        // Add two overlapping prefixes
        let p8 = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let p24 = Prefix::new(Ipv4Addr::new(10, 1, 2, 0), 24);
        rib.process_update(peer(1), 65001, &[p8.clone(), p24.clone()], &attrs, &[]);

        // 10.1.2.5 should match /24 (more specific)
        let (key, _) = rib.longest_match(Ipv4Addr::new(10, 1, 2, 5)).unwrap();
        assert_eq!(key.prefix_len, 24);

        // 10.2.0.1 should match /8 (less specific)
        let (key, _) = rib.longest_match(Ipv4Addr::new(10, 2, 0, 1)).unwrap();
        assert_eq!(key.prefix_len, 8);

        // 192.0.0.1 has no match
        assert!(rib.longest_match(Ipv4Addr::new(192, 0, 0, 1)).is_none());
    }

    #[test]
    fn test_longest_prefix_match_default_route() {
        let mut rib = Rib::new();
        let attrs = PathAttributes::default();
        // Default route 0.0.0.0/0
        let default = Prefix::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let specific = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        rib.process_update(peer(1), 65001, &[default.clone(), specific.clone()], &attrs, &[]);

        // 10.5.0.1 should prefer the /8
        let (key, _) = rib.longest_match(Ipv4Addr::new(10, 5, 0, 1)).unwrap();
        assert_eq!(key.prefix_len, 8);

        // 1.2.3.4 should fall back to the default route
        let (key, _) = rib.longest_match(Ipv4Addr::new(1, 2, 3, 4)).unwrap();
        assert_eq!(key.prefix_len, 0);
    }

    #[test]
    fn test_longest_prefix_match_empty_rib() {
        let rib = Rib::new();
        assert!(rib.longest_match(Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn test_graceful_restart_mark_stale() {
        let mut rib = Rib::new();
        let p = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let attrs = PathAttributes::default();
        rib.process_update(peer(1), 65001, &[p.clone()], &attrs, &[]);

        // Before marking: route is not stale
        assert!(!rib.adj_rib_in(&peer(1)).unwrap()[&PrefixKey::from(&p)].stale);

        rib.mark_peer_stale(peer(1));
        assert!(rib.adj_rib_in(&peer(1)).unwrap()[&PrefixKey::from(&p)].stale);
        // Loc-RIB still has the route (stale routes are still forwarded)
        assert_eq!(rib.prefix_count(), 1);
        assert_eq!(rib.stale_route_count(), 1);
    }

    #[test]
    fn test_graceful_restart_refresh_clears_stale() {
        let mut rib = Rib::new();
        let p = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let attrs = PathAttributes::default();
        rib.process_update(peer(1), 65001, &[p.clone()], &attrs, &[]);
        rib.mark_peer_stale(peer(1));

        // Peer reconnects and re-advertises the route
        rib.process_update(peer(1), 65001, &[p.clone()], &attrs, &[]);
        // process_update replaces with a fresh (non-stale) Route
        assert!(!rib.adj_rib_in(&peer(1)).unwrap()[&PrefixKey::from(&p)].stale);
        assert_eq!(rib.stale_route_count(), 0);
    }

    #[test]
    fn test_graceful_restart_remove_stale() {
        let mut rib = Rib::new();
        let p1 = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let p2 = Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let attrs = PathAttributes::default();
        rib.process_update(peer(1), 65001, &[p1.clone(), p2.clone()], &attrs, &[]);
        rib.mark_peer_stale(peer(1));

        // p1 is refreshed (no longer stale), p2 is not
        rib.process_update(peer(1), 65001, &[p1.clone()], &attrs, &[]);
        assert_eq!(rib.stale_route_count(), 1);

        // End-of-RIB / timer expiry: remove remaining stale routes
        let removed = rib.remove_stale_for_peer(peer(1));
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], PrefixKey::from(&p2));
        assert_eq!(rib.prefix_count(), 1); // only p1 remains
    }
}
