use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use crate::attr::PathAttributes;
use crate::message::update::Prefix;
use crate::rib::Rib;

/// Route Reflector role for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrRole {
    /// Not a route reflector peer.
    None,
    /// This peer is an RR client.
    Client,
    /// This peer is a non-client iBGP peer.
    NonClient,
}

/// Route Reflector configuration.
#[derive(Debug, Clone)]
pub struct RrConfig {
    /// This router's cluster ID (defaults to router ID if not set).
    pub cluster_id: Ipv4Addr,
    /// Whether this router acts as a route reflector.
    pub enabled: bool,
}

impl RrConfig {
    pub fn new(cluster_id: Ipv4Addr) -> Self {
        Self {
            cluster_id,
            enabled: true,
        }
    }
}

/// Route Reflector logic as defined in RFC 4456.
///
/// A route reflector (RR) reflects routes between its clients and non-client peers,
/// relieving the need for a full iBGP mesh.
///
/// Reflection rules:
/// 1. Routes from a **client**     → reflect to all clients + all non-clients
/// 2. Routes from a **non-client** → reflect to all clients only
/// 3. Routes from **eBGP**         → reflect to all clients + all non-clients
pub struct RouteReflector {
    pub config: RrConfig,
    pub router_id: Ipv4Addr,
}

impl RouteReflector {
    pub fn new(config: RrConfig, router_id: Ipv4Addr) -> Self {
        Self { config, router_id }
    }

    /// Determine whether to reflect a route to a target peer.
    ///
    /// - `source_role`: the role of the peer that sent the route
    /// - `target_role`: the role of the peer we're considering advertising to
    /// - `source_addr`: used to avoid reflecting back to the originator
    /// - `target_addr`: the candidate peer to advertise to
    pub fn should_reflect(
        &self,
        source_role: RrRole,
        target_role: RrRole,
        source_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> bool {
        if source_addr == target_addr {
            return false; // Never reflect back to originator
        }
        match (source_role, target_role) {
            // From eBGP peer or client → reflect to everyone
            (RrRole::None, _) => true, // eBGP → all iBGP
            (RrRole::Client, RrRole::Client) => true,
            (RrRole::Client, RrRole::NonClient) => true,
            // From non-client → reflect only to clients
            (RrRole::NonClient, RrRole::Client) => true,
            (RrRole::NonClient, RrRole::NonClient) => false,
            _ => false,
        }
    }

    /// Prepare path attributes for route reflection (RFC 4456 §8).
    ///
    /// When reflecting, the RR must:
    /// 1. Set ORIGINATOR_ID to the BGP ID of the originating router (if not already set)
    /// 2. Prepend its cluster ID to CLUSTER_LIST
    /// 3. NOT modify AS_PATH, LOCAL_PREF, MED, or NEXT_HOP
    pub fn prepare_reflected_attrs(
        &self,
        attrs: &PathAttributes,
        originator_id: Ipv4Addr,
    ) -> PathAttributes {
        let mut reflected = attrs.clone();

        // 1. Set ORIGINATOR_ID if not already set
        if reflected.originator_id.is_none() {
            reflected.originator_id = Some(originator_id);
        }

        // 2. Prepend cluster ID to CLUSTER_LIST
        reflected.cluster_list.insert(0, self.config.cluster_id);

        reflected
    }

    /// Loop detection: reject routes that contain our cluster ID in CLUSTER_LIST.
    ///
    /// RFC 4456 §8: If a route reflector receives an UPDATE with its own
    /// cluster ID in the CLUSTER_LIST, it must discard the route.
    pub fn has_cluster_loop(&self, attrs: &PathAttributes) -> bool {
        attrs.cluster_list.contains(&self.config.cluster_id)
    }

    /// Check ORIGINATOR_ID loop: reject if ORIGINATOR_ID equals our router ID.
    pub fn has_originator_loop(&self, attrs: &PathAttributes) -> bool {
        attrs.originator_id == Some(self.router_id)
    }

    /// Full loop check (either cluster or originator).
    pub fn has_loop(&self, attrs: &PathAttributes) -> bool {
        self.has_cluster_loop(attrs) || self.has_originator_loop(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::PathAttributes;

    fn make_rr() -> RouteReflector {
        let cfg = RrConfig::new(Ipv4Addr::new(10, 0, 0, 1));
        RouteReflector::new(cfg, Ipv4Addr::new(10, 0, 0, 1))
    }

    fn peer(n: u8) -> SocketAddr {
        format!("10.0.0.{}:179", n).parse().unwrap()
    }

    #[test]
    fn test_reflect_client_to_client() {
        let rr = make_rr();
        assert!(rr.should_reflect(RrRole::Client, RrRole::Client, peer(2), peer(3)));
    }

    #[test]
    fn test_reflect_client_to_non_client() {
        let rr = make_rr();
        assert!(rr.should_reflect(RrRole::Client, RrRole::NonClient, peer(2), peer(3)));
    }

    #[test]
    fn test_no_reflect_non_client_to_non_client() {
        let rr = make_rr();
        assert!(!rr.should_reflect(RrRole::NonClient, RrRole::NonClient, peer(2), peer(3)));
    }

    #[test]
    fn test_reflect_non_client_to_client() {
        let rr = make_rr();
        assert!(rr.should_reflect(RrRole::NonClient, RrRole::Client, peer(2), peer(3)));
    }

    #[test]
    fn test_no_reflect_to_originator() {
        let rr = make_rr();
        // Same source and target → never reflect
        assert!(!rr.should_reflect(RrRole::Client, RrRole::Client, peer(2), peer(2)));
    }

    #[test]
    fn test_cluster_loop_detection() {
        let rr = make_rr();
        let attrs = PathAttributes {
            cluster_list: vec![Ipv4Addr::new(10, 0, 0, 1)],
            ..Default::default()
        };
        assert!(rr.has_cluster_loop(&attrs));

        let attrs2 = PathAttributes {
            cluster_list: vec![Ipv4Addr::new(10, 0, 0, 99)],
            ..Default::default()
        };
        assert!(!rr.has_cluster_loop(&attrs2));
    }

    #[test]
    fn test_originator_loop_detection() {
        let rr = make_rr();
        let attrs = PathAttributes {
            originator_id: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        assert!(rr.has_originator_loop(&attrs));
    }

    #[test]
    fn test_prepare_reflected_attrs() {
        let rr = make_rr();
        let attrs = PathAttributes::default();
        let originator = Ipv4Addr::new(10, 0, 0, 5);
        let reflected = rr.prepare_reflected_attrs(&attrs, originator);

        assert_eq!(reflected.originator_id, Some(originator));
        assert_eq!(reflected.cluster_list, vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn test_cluster_list_prepend() {
        let rr = make_rr();
        let attrs = PathAttributes {
            cluster_list: vec![Ipv4Addr::new(10, 0, 0, 99)],
            ..Default::default()
        };
        let reflected = rr.prepare_reflected_attrs(&attrs, Ipv4Addr::new(10, 0, 0, 5));
        // Our cluster ID prepended
        assert_eq!(reflected.cluster_list[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(reflected.cluster_list[1], Ipv4Addr::new(10, 0, 0, 99));
    }

    #[test]
    fn test_originator_id_not_overwritten() {
        let rr = make_rr();
        let existing_originator = Ipv4Addr::new(10, 0, 0, 50);
        let attrs = PathAttributes {
            originator_id: Some(existing_originator),
            ..Default::default()
        };
        let reflected = rr.prepare_reflected_attrs(&attrs, Ipv4Addr::new(10, 0, 0, 99));
        // Should NOT be overwritten
        assert_eq!(reflected.originator_id, Some(existing_originator));
    }
}
