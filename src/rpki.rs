//! RPKI/ROA validation stub (RFC 6811, RFC 8893)
//!
//! Provides Route Origin Validation (ROV) state for BGP routes.
//! This is a stub implementation: it evaluates against a local ROA table
//! rather than using a live RTR client. A production implementation would
//! connect to an RTR server (RFC 6810) to fetch ROAs dynamically.
//!
//! # ROV Decision (RFC 6811 §2)
//!
//! Given a route with (prefix, origin_as):
//! - **Valid**:   At least one matching ROA covers the prefix and origin AS.
//! - **Invalid**: At least one ROA covers the prefix but the origin AS differs,
//!   or the prefix length exceeds the ROA's max-length.
//! - **NotFound**: No ROA covers the prefix at all.
//!
//! # RPKI Modes
//!
//! - **Disabled**: No validation; all routes are `NotFound`.
//! - **Loose**:    Validate and annotate routes; `Invalid` routes are accepted
//!   but flagged (useful for monitoring).
//! - **Strict**:   `Invalid` routes are rejected and not installed in the RIB.

use std::net::Ipv4Addr;

/// ROA (Route Origin Authorization) entry in the local table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roa {
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    /// Maximum prefix length this ROA covers (inclusive).
    pub max_length: u8,
    pub origin_as: u32,
}

impl Roa {
    pub fn new(prefix: Ipv4Addr, prefix_len: u8, max_length: u8, origin_as: u32) -> Self {
        Self {
            prefix,
            prefix_len,
            max_length,
            origin_as,
        }
    }

    /// True if this ROA covers the given prefix (address + length).
    pub fn covers(&self, addr: Ipv4Addr, len: u8) -> bool {
        if len < self.prefix_len || len > self.max_length {
            return false;
        }
        let bits = 32 - self.prefix_len;
        let roa_net = u32::from(self.prefix) >> bits << bits;
        let addr_net = u32::from(addr) >> bits << bits;
        roa_net == addr_net
    }
}

/// ROV validation state for a route (RFC 6811 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RovState {
    /// A matching ROA exists with the correct origin AS.
    Valid,
    /// A matching ROA exists but origin AS or max-length is wrong.
    Invalid,
    /// No ROA covers this prefix at all.
    #[default]
    NotFound,
}

impl std::fmt::Display for RovState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RovState::Valid => write!(f, "valid"),
            RovState::Invalid => write!(f, "invalid"),
            RovState::NotFound => write!(f, "not-found"),
        }
    }
}

/// RPKI operating mode configured by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RpkiMode {
    /// No validation; all routes are `NotFound`.
    #[default]
    Disabled,
    /// Validate and annotate; `Invalid` routes are still accepted.
    Loose,
    /// Validate; `Invalid` routes are rejected.
    Strict,
}

impl std::fmt::Display for RpkiMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpkiMode::Disabled => write!(f, "disabled"),
            RpkiMode::Loose => write!(f, "loose"),
            RpkiMode::Strict => write!(f, "strict"),
        }
    }
}

/// RPKI validator: holds a local ROA table and evaluates routes.
#[derive(Debug, Default)]
pub struct RpkiValidator {
    pub mode: RpkiMode,
    roas: Vec<Roa>,
}

impl RpkiValidator {
    pub fn new(mode: RpkiMode) -> Self {
        Self {
            mode,
            roas: Vec::new(),
        }
    }

    /// Add a ROA to the local table.
    pub fn add_roa(&mut self, roa: Roa) {
        self.roas.push(roa);
    }

    /// Validate a route against the local ROA table (RFC 6811 §2).
    pub fn validate(&self, prefix: Ipv4Addr, prefix_len: u8, origin_as: u32) -> RovState {
        if self.mode == RpkiMode::Disabled {
            return RovState::NotFound;
        }

        let covering: Vec<&Roa> = self
            .roas
            .iter()
            .filter(|r| r.covers(prefix, prefix_len))
            .collect();

        if covering.is_empty() {
            return RovState::NotFound;
        }

        // Valid if any covering ROA matches the origin AS
        if covering.iter().any(|r| r.origin_as == origin_as) {
            RovState::Valid
        } else {
            RovState::Invalid
        }
    }

    /// Returns true if a route with the given ROV state should be rejected
    /// under the current RPKI mode.
    pub fn should_reject(&self, state: RovState) -> bool {
        self.mode == RpkiMode::Strict && state == RovState::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator_with_roas() -> RpkiValidator {
        let mut v = RpkiValidator::new(RpkiMode::Strict);
        // 10.0.0.0/8 max /24 origin AS 65001
        v.add_roa(Roa::new(Ipv4Addr::new(10, 0, 0, 0), 8, 24, 65001));
        // 192.168.0.0/16 exact origin AS 65002
        v.add_roa(Roa::new(Ipv4Addr::new(192, 168, 0, 0), 16, 16, 65002));
        v
    }

    #[test]
    fn test_valid_route() {
        let v = validator_with_roas();
        // 10.1.0.0/24 from AS 65001 → covered by 10.0.0.0/8 max /24
        assert_eq!(
            v.validate(Ipv4Addr::new(10, 1, 0, 0), 24, 65001),
            RovState::Valid
        );
    }

    #[test]
    fn test_invalid_wrong_origin() {
        let v = validator_with_roas();
        // 10.1.0.0/24 from AS 65099 → covered but wrong AS
        assert_eq!(
            v.validate(Ipv4Addr::new(10, 1, 0, 0), 24, 65099),
            RovState::Invalid
        );
    }

    #[test]
    fn test_invalid_prefix_too_long() {
        let v = validator_with_roas();
        // 10.1.2.0/25 from AS 65001 → exceeds max_length /24
        assert_eq!(
            v.validate(Ipv4Addr::new(10, 1, 2, 0), 25, 65001),
            RovState::NotFound
        );
    }

    #[test]
    fn test_not_found() {
        let v = validator_with_roas();
        // 172.16.0.0/12 — no ROA covers this
        assert_eq!(
            v.validate(Ipv4Addr::new(172, 16, 0, 0), 12, 65001),
            RovState::NotFound
        );
    }

    #[test]
    fn test_disabled_mode_always_not_found() {
        let mut v = validator_with_roas();
        v.mode = RpkiMode::Disabled;
        // Even with matching ROAs, disabled mode returns NotFound
        assert_eq!(
            v.validate(Ipv4Addr::new(10, 1, 0, 0), 24, 65001),
            RovState::NotFound
        );
    }

    #[test]
    fn test_should_reject_strict() {
        let v = validator_with_roas(); // strict mode
        assert!(v.should_reject(RovState::Invalid));
        assert!(!v.should_reject(RovState::Valid));
        assert!(!v.should_reject(RovState::NotFound));
    }

    #[test]
    fn test_should_not_reject_loose() {
        let mut v = validator_with_roas();
        v.mode = RpkiMode::Loose;
        // Loose: annotate but never reject
        assert!(!v.should_reject(RovState::Invalid));
        assert!(!v.should_reject(RovState::Valid));
    }

    #[test]
    fn test_roa_covers_exact_length() {
        let roa = Roa::new(Ipv4Addr::new(192, 168, 0, 0), 16, 16, 65001);
        // Exact prefix length matches
        assert!(roa.covers(Ipv4Addr::new(192, 168, 0, 0), 16));
        // Prefix too short (more general)
        assert!(!roa.covers(Ipv4Addr::new(192, 168, 0, 0), 15));
        // Prefix too long (more specific than max_length)
        assert!(!roa.covers(Ipv4Addr::new(192, 168, 0, 0), 17));
    }

    #[test]
    fn test_roa_covers_subnet() {
        let roa = Roa::new(Ipv4Addr::new(10, 0, 0, 0), 8, 24, 65001);
        assert!(roa.covers(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert!(roa.covers(Ipv4Addr::new(10, 1, 0, 0), 16));
        assert!(roa.covers(Ipv4Addr::new(10, 1, 2, 0), 24));
        assert!(!roa.covers(Ipv4Addr::new(10, 1, 2, 0), 25)); // > max_length
        assert!(!roa.covers(Ipv4Addr::new(11, 0, 0, 0), 8)); // different network
    }

    #[test]
    fn test_rov_state_display() {
        assert_eq!(RovState::Valid.to_string(), "valid");
        assert_eq!(RovState::Invalid.to_string(), "invalid");
        assert_eq!(RovState::NotFound.to_string(), "not-found");
    }

    #[test]
    fn test_rpki_mode_display() {
        assert_eq!(RpkiMode::Disabled.to_string(), "disabled");
        assert_eq!(RpkiMode::Loose.to_string(), "loose");
        assert_eq!(RpkiMode::Strict.to_string(), "strict");
    }
}
