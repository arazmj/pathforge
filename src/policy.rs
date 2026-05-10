#![allow(dead_code, unused_variables)]

use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::attr::{Community, PathAttributes};
use crate::config::{FilterAction, PolicyConfig, PrefixList, PrefixListEntry};
use crate::message::update::Prefix;

/// Route filtering engine: evaluates prefix lists and community lists against routes.
pub struct PolicyEngine {
    policy: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(policy: PolicyConfig) -> Self {
        Self { policy }
    }

    /// Check whether a route (prefix + attributes) passes an import/export policy.
    ///
    /// Returns `true` if the route should be accepted.
    pub fn apply(&self, policy_name: &str, prefix: &Prefix, attrs: &PathAttributes) -> bool {
        // Find the prefix list with the given name
        if let Some(pl) = self
            .policy
            .prefix_lists
            .iter()
            .find(|p| p.name == policy_name)
        {
            return self.evaluate_prefix_list(pl, prefix, attrs);
        }
        // No matching policy: default permit
        true
    }

    fn evaluate_prefix_list(
        &self,
        list: &PrefixList,
        prefix: &Prefix,
        attrs: &PathAttributes,
    ) -> bool {
        for entry in &list.entries {
            if self.matches_entry(entry, prefix) {
                return entry.action == FilterAction::Permit;
            }
        }
        // Implicit deny at end of prefix list
        false
    }

    fn matches_entry(&self, entry: &PrefixListEntry, prefix: &Prefix) -> bool {
        let (net_addr, net_len) = match parse_prefix(&entry.prefix) {
            Some(v) => v,
            None => return false,
        };

        // The route prefix must be within the entry's network
        if !is_subnet(prefix.address, prefix.prefix_len, net_addr, net_len) {
            return false;
        }

        // Check ge/le range constraints on the prefix length
        let pl = prefix.prefix_len;
        let ge_ok = entry.ge.map(|ge| pl >= ge).unwrap_or(true);
        let le_ok = entry.le.map(|le| pl <= le).unwrap_or(true);
        // Without ge/le: exact prefix match required
        let exact_ok = if entry.ge.is_none() && entry.le.is_none() {
            pl == net_len
        } else {
            true
        };

        ge_ok && le_ok && exact_ok
    }

    /// Test whether attributes contain a specific community string.
    pub fn has_community(&self, attrs: &PathAttributes, community_str: &str) -> bool {
        if let Some(c) = parse_community_str(community_str) {
            return attrs.communities.contains(&c);
        }
        false
    }

    /// Test whether attributes match a named community list.
    pub fn matches_community_list(&self, list_name: &str, attrs: &PathAttributes) -> bool {
        if let Some(cl) = self
            .policy
            .community_lists
            .iter()
            .find(|c| c.name == list_name)
        {
            return cl.communities.iter().any(|c| self.has_community(attrs, c));
        }
        false
    }
}

/// Parse "1.2.3.0/24" into (Ipv4Addr, u8).
fn parse_prefix(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr_str, len_str) = s.split_once('/')?;
    let addr = Ipv4Addr::from_str(addr_str).ok()?;
    let len: u8 = len_str.parse().ok()?;
    Some((addr, len))
}

/// Returns true if `test_addr/test_len` is a subnet of `net_addr/net_len`.
fn is_subnet(test_addr: Ipv4Addr, test_len: u8, net_addr: Ipv4Addr, net_len: u8) -> bool {
    if test_len < net_len {
        return false;
    }
    if net_len == 0 {
        return true; // 0.0.0.0/0 matches everything
    }
    let mask = !((1u32 << (32 - net_len)) - 1);
    let net_masked = u32::from(net_addr) & mask;
    let test_masked = u32::from(test_addr) & mask;
    net_masked == test_masked
}

/// Parse a community string like "65001:100" or well-known names.
fn parse_community_str(s: &str) -> Option<Community> {
    match s {
        "no-export" => Some(Community::NO_EXPORT),
        "no-advertise" => Some(Community::NO_ADVERTISE),
        "no-export-subconfed" => Some(Community::NO_EXPORT_SUBCONFED),
        _ => {
            let (asn_str, val_str) = s.split_once(':')?;
            let asn: u16 = asn_str.parse().ok()?;
            let val: u16 = val_str.parse().ok()?;
            Some(Community(((asn as u32) << 16) | val as u32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CommunityList, FilterAction, PolicyConfig, PrefixList, PrefixListEntry};

    fn make_engine() -> PolicyEngine {
        PolicyEngine::new(PolicyConfig {
            prefix_lists: vec![
                PrefixList {
                    name: "allow-rfc1918".to_string(),
                    entries: vec![
                        PrefixListEntry {
                            action: FilterAction::Permit,
                            prefix: "10.0.0.0/8".to_string(),
                            ge: Some(8),
                            le: Some(24),
                        },
                        PrefixListEntry {
                            action: FilterAction::Permit,
                            prefix: "192.168.0.0/16".to_string(),
                            ge: None,
                            le: None,
                        },
                        PrefixListEntry {
                            action: FilterAction::Deny,
                            prefix: "0.0.0.0/0".to_string(),
                            ge: None,
                            le: None,
                        },
                    ],
                },
                PrefixList {
                    name: "exact-only".to_string(),
                    entries: vec![PrefixListEntry {
                        action: FilterAction::Permit,
                        prefix: "172.16.0.0/12".to_string(),
                        ge: None,
                        le: None,
                    }],
                },
            ],
            community_lists: vec![CommunityList {
                name: "no-export-comms".to_string(),
                communities: vec!["no-export".to_string(), "65001:100".to_string()],
            }],
        })
    }

    fn prefix(addr: &str, len: u8) -> Prefix {
        Prefix::new(addr.parse().unwrap(), len)
    }

    #[test]
    fn test_permit_in_range() {
        let eng = make_engine();
        let attrs = PathAttributes::default();
        // 10.0.0.0/8 is ge=8 le=24 → /8 should match
        assert!(eng.apply("allow-rfc1918", &prefix("10.0.0.0", 8), &attrs));
        // 10.1.0.0/16 is within 10.0.0.0/8 and 8<=16<=24
        assert!(eng.apply("allow-rfc1918", &prefix("10.1.0.0", 16), &attrs));
        // 10.0.0.0/25 exceeds le=24 → deny (falls to default deny)
        assert!(!eng.apply("allow-rfc1918", &prefix("10.0.0.0", 25), &attrs));
    }

    #[test]
    fn test_exact_prefix_match() {
        let eng = make_engine();
        let attrs = PathAttributes::default();
        // 192.168.0.0/16 exact → permit
        assert!(eng.apply("allow-rfc1918", &prefix("192.168.0.0", 16), &attrs));
        // 192.168.1.0/24 not an exact /16 match → deny
        assert!(!eng.apply("allow-rfc1918", &prefix("192.168.1.0", 24), &attrs));
    }

    #[test]
    fn test_exact_only_policy() {
        let eng = make_engine();
        let attrs = PathAttributes::default();
        // 172.16.0.0/12 exact match
        assert!(eng.apply("exact-only", &prefix("172.16.0.0", 12), &attrs));
        // 172.16.1.0/24 not exact → deny
        assert!(!eng.apply("exact-only", &prefix("172.16.1.0", 24), &attrs));
    }

    #[test]
    fn test_unknown_policy_default_permit() {
        let eng = make_engine();
        let attrs = PathAttributes::default();
        assert!(eng.apply("nonexistent", &prefix("1.2.3.0", 24), &attrs));
    }

    #[test]
    fn test_community_matching() {
        let eng = make_engine();
        let attrs = PathAttributes {
            communities: vec![Community::NO_EXPORT],
            ..Default::default()
        };
        assert!(eng.matches_community_list("no-export-comms", &attrs));

        let attrs2 = PathAttributes {
            communities: vec![Community(((65001u32) << 16) | 100)],
            ..Default::default()
        };
        assert!(eng.matches_community_list("no-export-comms", &attrs2));

        let attrs3 = PathAttributes::default();
        assert!(!eng.matches_community_list("no-export-comms", &attrs3));
    }

    #[test]
    fn test_community_parse() {
        assert_eq!(parse_community_str("no-export"), Some(Community::NO_EXPORT));
        let c = parse_community_str("65001:200").unwrap();
        assert_eq!(c.asn(), 65001);
        assert_eq!(c.value(), 200);
        assert!(parse_community_str("invalid").is_none());
    }

    #[test]
    fn test_is_subnet() {
        // 10.1.0.0/16 is a subnet of 10.0.0.0/8
        assert!(is_subnet(
            "10.1.0.0".parse().unwrap(),
            16,
            "10.0.0.0".parse().unwrap(),
            8
        ));
        // 192.168.0.0/16 is not a subnet of 10.0.0.0/8
        assert!(!is_subnet(
            "192.168.0.0".parse().unwrap(),
            16,
            "10.0.0.0".parse().unwrap(),
            8
        ));
        // 0.0.0.0/0 matches everything
        assert!(is_subnet(
            "1.2.3.4".parse().unwrap(),
            32,
            "0.0.0.0".parse().unwrap(),
            0
        ));
    }
}
