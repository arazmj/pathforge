//! BGP Capability negotiation (RFC 5492, RFC 4760, RFC 6793, RFC 4724, RFC 2918)

use std::fmt;

/// Well-known BGP capability codes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// RFC 4760 — Multi-Protocol Extensions
    MultiProtocol { afi: u16, safi: u8 },
    /// RFC 2918 — Route Refresh
    RouteRefresh,
    /// RFC 6793 — 4-byte AS number
    FourOctetAsn { asn: u32 },
    /// RFC 4724 — Graceful Restart
    GracefulRestart { restart_time: u16, flags: u8 },
    /// Unknown capability (pass-through)
    Unknown { code: u8, data: Vec<u8> },
}

impl Capability {
    #[allow(dead_code)]
    pub fn code(&self) -> u8 {
        match self {
            Self::MultiProtocol { .. } => 1,
            Self::RouteRefresh => 2,
            Self::GracefulRestart { .. } => 64,
            Self::FourOctetAsn { .. } => 65,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Serialize this capability to wire format (code + length + value)
    pub fn to_bytes(&self) -> Vec<u8> {
        let (code, value) = match self {
            Self::MultiProtocol { afi, safi } => {
                (1u8, vec![(afi >> 8) as u8, *afi as u8, 0, *safi])
            }
            Self::RouteRefresh => (2u8, vec![]),
            Self::GracefulRestart {
                restart_time,
                flags,
            } => {
                let word = (((*flags as u16) & 0xF) << 12) | (restart_time & 0x0FFF);
                (64u8, vec![(word >> 8) as u8, word as u8])
            }
            Self::FourOctetAsn { asn } => {
                let b = asn.to_be_bytes();
                (65u8, b.to_vec())
            }
            Self::Unknown { code, data } => (*code, data.clone()),
        };
        let mut out = vec![code, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }

    /// Parse capabilities from already-decoded `OptionalParam` list (from a parsed OPEN).
    pub fn parse_from_open_params(
        params: &[crate::message::open::OptionalParam],
    ) -> Vec<Capability> {
        let mut raw = Vec::new();
        for p in params {
            raw.push(p.param_type);
            raw.push(p.value.len() as u8);
            raw.extend_from_slice(&p.value);
        }
        Self::parse_optional_params(&raw)
    }

    /// Parse capabilities from the optional parameters section of a BGP OPEN message.
    /// `data` is the raw bytes of the optional parameters (after the opt param length byte).
    pub fn parse_optional_params(data: &[u8]) -> Vec<Capability> {
        let mut caps = Vec::new();
        let mut pos = 0;
        while pos + 2 <= data.len() {
            let param_type = data[pos];
            let param_len = data[pos + 1] as usize;
            pos += 2;
            if param_type == 2 {
                // Capability optional parameter
                let end = pos + param_len;
                let mut cap_pos = pos;
                while cap_pos + 2 <= end.min(data.len()) {
                    let cap_code = data[cap_pos];
                    let cap_len = data[cap_pos + 1] as usize;
                    cap_pos += 2;
                    let cap_end = cap_pos + cap_len;
                    if cap_end > data.len() {
                        break;
                    }
                    let cap_data = &data[cap_pos..cap_end];
                    let cap = Self::parse_one(cap_code, cap_data);
                    caps.push(cap);
                    cap_pos = cap_end;
                }
            }
            pos += param_len;
        }
        caps
    }

    fn parse_one(code: u8, data: &[u8]) -> Capability {
        match code {
            1 if data.len() >= 4 => Capability::MultiProtocol {
                afi: u16::from_be_bytes([data[0], data[1]]),
                safi: data[3],
            },
            2 => Capability::RouteRefresh,
            64 if data.len() >= 2 => {
                let word = u16::from_be_bytes([data[0], data[1]]);
                Capability::GracefulRestart {
                    flags: ((word >> 12) & 0xF) as u8,
                    restart_time: word & 0x0FFF,
                }
            }
            65 if data.len() >= 4 => Capability::FourOctetAsn {
                asn: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            },
            _ => Capability::Unknown {
                code,
                data: data.to_vec(),
            },
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiProtocol { afi, safi } => write!(f, "MultiProtocol(AFI={afi}, SAFI={safi})"),
            Self::RouteRefresh => write!(f, "RouteRefresh"),
            Self::GracefulRestart { restart_time, .. } => {
                write!(f, "GracefulRestart(time={restart_time}s)")
            }
            Self::FourOctetAsn { asn } => write!(f, "4-byte-ASN({asn})"),
            Self::Unknown { code, .. } => write!(f, "Unknown(code={code})"),
        }
    }
}

/// Build the capability optional parameters block for a BGP OPEN message
#[allow(dead_code)]
pub fn build_capabilities(caps: &[Capability]) -> Vec<u8> {
    // Encode as a single type=2 optional parameter containing all capabilities
    let mut cap_bytes = Vec::new();
    for cap in caps {
        cap_bytes.extend_from_slice(&cap.to_bytes());
    }
    if cap_bytes.is_empty() {
        return vec![0]; // opt param length = 0
    }
    // opt param: type=2, len=cap_bytes.len(), data
    let mut out = Vec::new();
    out.push(2u8); // param type: Capability
    out.push(cap_bytes.len() as u8); // param length
    out.extend_from_slice(&cap_bytes);
    // prepend total opt param length
    let mut result = vec![(out.len()) as u8];
    result.extend_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_refresh_roundtrip() {
        let cap = Capability::RouteRefresh;
        let bytes = cap.to_bytes();
        assert_eq!(bytes, vec![2, 0]);
    }

    #[test]
    fn test_four_octet_asn_roundtrip() {
        let cap = Capability::FourOctetAsn { asn: 131072 };
        let bytes = cap.to_bytes();
        assert_eq!(bytes, vec![65, 4, 0, 2, 0, 0]);
        let parsed = Capability::parse_one(65, &bytes[2..]);
        assert_eq!(parsed, Capability::FourOctetAsn { asn: 131072 });
    }

    #[test]
    fn test_multiprotocol_ipv6() {
        let cap = Capability::MultiProtocol { afi: 2, safi: 1 };
        let bytes = cap.to_bytes();
        assert_eq!(bytes[0], 1);
        let parsed = Capability::parse_one(1, &bytes[2..]);
        assert_eq!(parsed, Capability::MultiProtocol { afi: 2, safi: 1 });
    }

    #[test]
    fn test_graceful_restart() {
        let cap = Capability::GracefulRestart {
            restart_time: 120,
            flags: 0x8,
        };
        let bytes = cap.to_bytes();
        let parsed = Capability::parse_one(64, &bytes[2..]);
        assert!(matches!(
            parsed,
            Capability::GracefulRestart {
                restart_time: 120,
                ..
            }
        ));
    }

    #[test]
    fn test_build_capabilities_block() {
        let caps = vec![
            Capability::RouteRefresh,
            Capability::FourOctetAsn { asn: 65001 },
        ];
        let block = build_capabilities(&caps);
        // First byte is total opt param length
        assert!(block.len() > 2);
        // Parse them back
        let parsed = Capability::parse_optional_params(&block[1..]);
        assert!(parsed.contains(&Capability::RouteRefresh));
        assert!(parsed.contains(&Capability::FourOctetAsn { asn: 65001 }));
    }

    #[test]
    fn test_unknown_capability() {
        let parsed = Capability::parse_one(99, &[0xAA, 0xBB]);
        assert!(matches!(parsed, Capability::Unknown { code: 99, .. }));
    }

    #[test]
    fn test_display() {
        assert_eq!(Capability::RouteRefresh.to_string(), "RouteRefresh");
        assert_eq!(
            Capability::FourOctetAsn { asn: 65000 }.to_string(),
            "4-byte-ASN(65000)"
        );
    }
}
