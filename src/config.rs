use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

/// Top-level PathForge configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub router: RouterConfig,
    #[serde(default)]
    pub neighbors: Vec<NeighborConfig>,
    #[serde(default)]
    pub policy: PolicyConfig,
}

/// Global router settings.
#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    /// Local AS number.
    pub local_as: u32,
    /// BGP router ID (IPv4 address).
    pub router_id: Ipv4Addr,
    /// BGP listen address.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Hold time in seconds (0 or ≥3, default 90).
    #[serde(default = "default_hold_time")]
    pub hold_time: u16,
    /// Keepalive interval in seconds (default: hold_time / 3).
    #[allow(dead_code)]
    #[serde(default)]
    pub keepalive_interval: Option<u16>,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:179".parse().expect("valid default listen address")
}

fn default_hold_time() -> u16 {
    90
}

/// Per-neighbor (peer) configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct NeighborConfig {
    /// Peer IP address.
    pub addr: IpAddr,
    /// Peer's AS number.
    pub remote_as: u32,
    /// Override hold time for this peer.
    pub hold_time: Option<u16>,
    /// Description for this neighbor.
    pub description: Option<String>,
    /// Whether this is a route reflector client.
    #[serde(default)]
    pub route_reflector_client: bool,
    /// Import policy name (applied to routes received from this peer).
    pub import_policy: Option<String>,
    /// Export policy name (applied to routes sent to this peer).
    pub export_policy: Option<String>,
}

impl NeighborConfig {
    #[allow(dead_code)]
    pub fn socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.addr, port)
    }
}

/// Route policy configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyConfig {
    /// Named prefix lists.
    #[serde(default)]
    pub prefix_lists: Vec<PrefixList>,
    /// Named community lists.
    #[serde(default)]
    pub community_lists: Vec<CommunityList>,
}

/// A named prefix list for route filtering.
#[derive(Debug, Clone, Deserialize)]
pub struct PrefixList {
    pub name: String,
    pub entries: Vec<PrefixListEntry>,
}

/// A single prefix-list entry.
#[derive(Debug, Clone, Deserialize)]
pub struct PrefixListEntry {
    pub action: FilterAction,
    pub prefix: String,
    pub ge: Option<u8>,
    pub le: Option<u8>,
}

/// A named community list for route filtering.
#[derive(Debug, Clone, Deserialize)]
pub struct CommunityList {
    pub name: String,
    pub communities: Vec<String>,
}

/// Filter action (permit/deny).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Permit,
    Deny,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| "Failed to parse TOML configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Parse configuration from a TOML string.
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Result<Self> {
        let config: Config = toml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        // AS number: must be non-zero (0 is reserved, RFC 7607)
        if self.router.local_as == 0 {
            anyhow::bail!("local_as must be non-zero");
        }

        // Router ID: 0.0.0.0 and 255.255.255.255 are invalid per RFC 4271
        let rid = self.router.router_id;
        if rid.is_unspecified() {
            anyhow::bail!("router_id must not be 0.0.0.0");
        }
        if rid.octets() == [255, 255, 255, 255] {
            anyhow::bail!("router_id must not be 255.255.255.255");
        }
        if rid.is_loopback() {
            anyhow::bail!("router_id must not be a loopback address (127.x.x.x)");
        }

        // Hold time: RFC 4271 §4.2 — must be 0 or >= 3 seconds
        if self.router.hold_time != 0 && self.router.hold_time < 3 {
            anyhow::bail!("hold_time must be 0 or >= 3 seconds (RFC 4271)");
        }

        // Keepalive interval: if explicitly set, must be > 0 and < hold_time
        if let Some(ka) = self.router.keepalive_interval {
            if ka == 0 {
                anyhow::bail!("keepalive_interval must be > 0");
            }
            if self.router.hold_time != 0 && ka >= self.router.hold_time {
                anyhow::bail!("keepalive_interval must be less than hold_time");
            }
        }

        // Neighbors: no duplicate addresses, no zero remote_as
        let mut seen_addrs = std::collections::HashSet::new();
        for n in &self.neighbors {
            if !seen_addrs.insert(n.addr) {
                anyhow::bail!("duplicate neighbor address: {}", n.addr);
            }
            if n.remote_as == 0 {
                anyhow::bail!("neighbor {}: remote_as must be non-zero", n.addr);
            }
            // Per-neighbor hold_time follows the same rule as global
            if let Some(ht) = n.hold_time {
                if ht != 0 && ht < 3 {
                    anyhow::bail!(
                        "neighbor {}: hold_time must be 0 or >= 3 seconds",
                        n.addr
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
[router]
local_as = 65001
router_id = "10.0.0.1"
listen = "0.0.0.0:179"
hold_time = 90

[[neighbors]]
addr = "192.168.1.2"
remote_as = 65002
description = "Upstream provider"
import_policy = "import-from-upstream"

[[neighbors]]
addr = "10.0.0.2"
remote_as = 65001
description = "iBGP peer"
route_reflector_client = true

[policy]
[[policy.prefix_lists]]
name = "allowed-prefixes"
entries = [
    { action = "permit", prefix = "10.0.0.0/8" },
    { action = "permit", prefix = "172.16.0.0/12", ge = 24, le = 32 },
    { action = "deny",   prefix = "0.0.0.0/0" },
]

[[policy.community_lists]]
name = "no-export-comms"
communities = ["no-export", "65001:100"]
"#;

    #[test]
    fn test_parse_full_config() {
        let cfg = Config::from_str(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.router.local_as, 65001);
        assert_eq!(cfg.router.router_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(cfg.router.hold_time, 90);
        assert_eq!(cfg.neighbors.len(), 2);
        assert_eq!(cfg.neighbors[0].remote_as, 65002);
        assert!(cfg.neighbors[1].route_reflector_client);
        assert_eq!(cfg.policy.prefix_lists.len(), 1);
        assert_eq!(cfg.policy.prefix_lists[0].entries.len(), 3);
        assert_eq!(cfg.policy.community_lists.len(), 1);
    }

    #[test]
    fn test_minimal_config() {
        let s = r#"
[router]
local_as = 65000
router_id = "1.2.3.4"
"#;
        let cfg = Config::from_str(s).unwrap();
        assert_eq!(cfg.router.local_as, 65000);
        assert!(cfg.neighbors.is_empty());
    }

    #[test]
    fn test_invalid_hold_time() {
        let s = r#"
[router]
local_as = 65000
router_id = "1.2.3.4"
hold_time = 2
"#;
        assert!(Config::from_str(s).is_err());
    }

    #[test]
    fn test_invalid_as() {
        let s = r#"
[router]
local_as = 0
router_id = "1.2.3.4"
"#;
        assert!(Config::from_str(s).is_err());
    }

    #[test]
    fn test_invalid_router_id_unspecified() {
        let s = r#"
[router]
local_as = 65000
router_id = "0.0.0.0"
"#;
        let err = Config::from_str(s).unwrap_err().to_string();
        assert!(err.contains("0.0.0.0"), "expected 0.0.0.0 error, got: {err}");
    }

    #[test]
    fn test_invalid_router_id_broadcast() {
        let s = r#"
[router]
local_as = 65000
router_id = "255.255.255.255"
"#;
        assert!(Config::from_str(s).is_err());
    }

    #[test]
    fn test_invalid_router_id_loopback() {
        let s = r#"
[router]
local_as = 65000
router_id = "127.0.0.1"
"#;
        assert!(Config::from_str(s).is_err());
    }

    #[test]
    fn test_duplicate_neighbor() {
        let s = r#"
[router]
local_as = 65000
router_id = "1.2.3.4"

[[neighbors]]
addr = "10.0.0.1"
remote_as = 65001

[[neighbors]]
addr = "10.0.0.1"
remote_as = 65002
"#;
        let err = Config::from_str(s).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "expected duplicate error, got: {err}");
    }

    #[test]
    fn test_neighbor_zero_remote_as() {
        let s = r#"
[router]
local_as = 65000
router_id = "1.2.3.4"

[[neighbors]]
addr = "10.0.0.1"
remote_as = 0
"#;
        assert!(Config::from_str(s).is_err());
    }

    #[test]
    fn test_invalid_keepalive_interval() {
        let s = r#"
[router]
local_as = 65000
router_id = "1.2.3.4"
hold_time = 90
keepalive_interval = 100
"#;
        let err = Config::from_str(s).unwrap_err().to_string();
        assert!(
            err.contains("keepalive_interval"),
            "expected keepalive error, got: {err}"
        );
    }
}
