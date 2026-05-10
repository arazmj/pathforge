use bytes::{Buf, BufMut, BytesMut};
use std::net::Ipv4Addr;
use thiserror::Error;

/// BGP path attribute type codes (RFC 4271 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,    // RFC 1997
    OriginatorId = 9,   // RFC 4456
    ClusterId = 10,     // RFC 4456
    MpReachNlri = 14,   // RFC 4760
    MpUnreachNlri = 15, // RFC 4760
}

/// ORIGIN attribute values (RFC 4271 §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl TryFrom<u8> for Origin {
    type Error = AttrError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Origin::Igp),
            1 => Ok(Origin::Egp),
            2 => Ok(Origin::Incomplete),
            _ => Err(AttrError::InvalidOrigin(v)),
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Igp => write!(f, "IGP"),
            Origin::Egp => write!(f, "EGP"),
            Origin::Incomplete => write!(f, "Incomplete"),
        }
    }
}

/// AS_PATH segment types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    AsSet(Vec<u32>),
    AsSequence(Vec<u32>),
}

impl AsPathSegment {
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        match self {
            AsPathSegment::AsSet(v) | AsPathSegment::AsSequence(v) => v.len(),
        }
    }
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_numbers(&self) -> &[u32] {
        match self {
            AsPathSegment::AsSet(v) | AsPathSegment::AsSequence(v) => v,
        }
    }
}

#[derive(Debug, Error)]
pub enum AttrError {
    #[error("Attribute too short")]
    TooShort,
    #[error("Invalid ORIGIN value: {0}")]
    InvalidOrigin(u8),
    #[error("Invalid AS_PATH segment type: {0}")]
    InvalidAsPathSegment(u8),
    #[allow(dead_code)]
    #[error("Parse error: {0}")]
    Parse(String),
}

/// Parsed BGP path attributes.
#[derive(Debug, Clone, Default)]
pub struct PathAttributes {
    pub origin: Option<Origin>,
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: Option<Ipv4Addr>,
    pub multi_exit_disc: Option<u32>,
    pub local_pref: Option<u32>,
    pub atomic_aggregate: bool,
    pub aggregator: Option<(u16, Ipv4Addr)>,
    pub communities: Vec<Community>,
    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: Vec<Ipv4Addr>,
    /// Unknown attributes stored as raw bytes for pass-through.
    pub unknown: Vec<RawAttribute>,
}

/// A BGP community value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Community(pub u32);

impl Community {
    pub const NO_EXPORT: Community = Community(0xFFFF_FF01);
    pub const NO_ADVERTISE: Community = Community(0xFFFF_FF02);
    pub const NO_EXPORT_SUBCONFED: Community = Community(0xFFFF_FF03);

    pub fn asn(&self) -> u16 {
        (self.0 >> 16) as u16
    }
    pub fn value(&self) -> u16 {
        self.0 as u16
    }
}

impl std::fmt::Display for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Community::NO_EXPORT => write!(f, "no-export"),
            Community::NO_ADVERTISE => write!(f, "no-advertise"),
            Community::NO_EXPORT_SUBCONFED => write!(f, "no-export-subconfed"),
            _ => write!(f, "{}:{}", self.asn(), self.value()),
        }
    }
}

/// Raw unknown attribute for pass-through.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawAttribute {
    pub flags: u8,
    pub type_code: u8,
    pub value: Vec<u8>,
}

/// Path attribute flags (RFC 4271 §4.3).
#[allow(dead_code)]
const FLAG_OPTIONAL: u8 = 0x80;
#[allow(dead_code)]
const FLAG_TRANSITIVE: u8 = 0x40;
const FLAG_EXTENDED_LEN: u8 = 0x10;

impl PathAttributes {
    /// True when no attributes are set (RFC 4724 End-of-RIB detection).
    pub fn is_empty(&self) -> bool {
        self.origin.is_none()
            && self.as_path.is_empty()
            && self.next_hop.is_none()
            && self.multi_exit_disc.is_none()
            && self.local_pref.is_none()
            && !self.atomic_aggregate
            && self.aggregator.is_none()
            && self.communities.is_empty()
            && self.originator_id.is_none()
            && self.cluster_list.is_empty()
            && self.unknown.is_empty()
    }

    /// Parse all path attributes from a raw byte buffer.
    pub fn parse(mut buf: impl Buf) -> Result<Self, AttrError> {
        let mut attrs = PathAttributes::default();
        while buf.remaining() >= 3 {
            let flags = buf.get_u8();
            let type_code = buf.get_u8();
            let length = if flags & FLAG_EXTENDED_LEN != 0 {
                if buf.remaining() < 2 {
                    return Err(AttrError::TooShort);
                }
                buf.get_u16() as usize
            } else {
                if buf.remaining() < 1 {
                    return Err(AttrError::TooShort);
                }
                buf.get_u8() as usize
            };
            if buf.remaining() < length {
                return Err(AttrError::TooShort);
            }
            let value = buf.copy_to_bytes(length);

            match type_code {
                1 => {
                    // ORIGIN
                    if value.is_empty() {
                        return Err(AttrError::TooShort);
                    }
                    attrs.origin = Some(Origin::try_from(value[0])?);
                }
                2 => {
                    // AS_PATH (4-byte AS support)
                    let mut seg_buf = value.clone();
                    while seg_buf.remaining() >= 2 {
                        let seg_type = seg_buf.get_u8();
                        let seg_len = seg_buf.get_u8() as usize;
                        if seg_buf.remaining() < seg_len * 4 {
                            return Err(AttrError::TooShort);
                        }
                        let mut asns = Vec::with_capacity(seg_len);
                        for _ in 0..seg_len {
                            asns.push(seg_buf.get_u32());
                        }
                        let seg = match seg_type {
                            1 => AsPathSegment::AsSet(asns),
                            2 => AsPathSegment::AsSequence(asns),
                            _ => return Err(AttrError::InvalidAsPathSegment(seg_type)),
                        };
                        attrs.as_path.push(seg);
                    }
                }
                3 => {
                    // NEXT_HOP
                    if value.len() < 4 {
                        return Err(AttrError::TooShort);
                    }
                    let mut b = value.clone();
                    attrs.next_hop = Some(Ipv4Addr::from(b.get_u32()));
                }
                4 => {
                    // MULTI_EXIT_DISC
                    if value.len() < 4 {
                        return Err(AttrError::TooShort);
                    }
                    let mut b = value.clone();
                    attrs.multi_exit_disc = Some(b.get_u32());
                }
                5 => {
                    // LOCAL_PREF
                    if value.len() < 4 {
                        return Err(AttrError::TooShort);
                    }
                    let mut b = value.clone();
                    attrs.local_pref = Some(b.get_u32());
                }
                6 => {
                    // ATOMIC_AGGREGATE
                    attrs.atomic_aggregate = true;
                }
                7 => {
                    // AGGREGATOR
                    if value.len() < 6 {
                        return Err(AttrError::TooShort);
                    }
                    let mut b = value.clone();
                    let asn = b.get_u16();
                    let ip = Ipv4Addr::from(b.get_u32());
                    attrs.aggregator = Some((asn, ip));
                }
                8 => {
                    // COMMUNITIES (RFC 1997)
                    let mut b = value.clone();
                    while b.remaining() >= 4 {
                        attrs.communities.push(Community(b.get_u32()));
                    }
                }
                9 => {
                    // ORIGINATOR_ID (RFC 4456)
                    if value.len() < 4 {
                        return Err(AttrError::TooShort);
                    }
                    let mut b = value.clone();
                    attrs.originator_id = Some(Ipv4Addr::from(b.get_u32()));
                }
                10 => {
                    // CLUSTER_LIST (RFC 4456)
                    let mut b = value.clone();
                    while b.remaining() >= 4 {
                        attrs.cluster_list.push(Ipv4Addr::from(b.get_u32()));
                    }
                }
                _ => {
                    attrs.unknown.push(RawAttribute {
                        flags,
                        type_code,
                        value: value.to_vec(),
                    });
                }
            }
        }
        Ok(attrs)
    }

    /// Serialize all path attributes into a byte buffer.
    #[allow(dead_code)]
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        if let Some(origin) = self.origin {
            Self::write_attr(&mut buf, FLAG_TRANSITIVE, 1, &[origin as u8]);
        }

        if !self.as_path.is_empty() {
            let mut seg_buf = BytesMut::new();
            for seg in &self.as_path {
                let (seg_type, asns) = match seg {
                    AsPathSegment::AsSet(v) => (1u8, v),
                    AsPathSegment::AsSequence(v) => (2u8, v),
                };
                seg_buf.put_u8(seg_type);
                seg_buf.put_u8(asns.len() as u8);
                for &asn in asns {
                    seg_buf.put_u32(asn);
                }
            }
            Self::write_attr(&mut buf, FLAG_TRANSITIVE, 2, &seg_buf);
        }

        if let Some(nh) = self.next_hop {
            Self::write_attr(&mut buf, FLAG_TRANSITIVE, 3, &u32::from(nh).to_be_bytes());
        }

        if let Some(med) = self.multi_exit_disc {
            Self::write_attr(&mut buf, FLAG_OPTIONAL, 4, &med.to_be_bytes());
        }

        if let Some(lp) = self.local_pref {
            Self::write_attr(&mut buf, FLAG_TRANSITIVE, 5, &lp.to_be_bytes());
        }

        if self.atomic_aggregate {
            Self::write_attr(&mut buf, FLAG_TRANSITIVE, 6, &[]);
        }

        if let Some((asn, ip)) = self.aggregator {
            let mut v = BytesMut::new();
            v.put_u16(asn);
            v.put_u32(u32::from(ip));
            Self::write_attr(&mut buf, FLAG_OPTIONAL | FLAG_TRANSITIVE, 7, &v);
        }

        if !self.communities.is_empty() {
            let mut v = BytesMut::new();
            for c in &self.communities {
                v.put_u32(c.0);
            }
            Self::write_attr(&mut buf, FLAG_OPTIONAL | FLAG_TRANSITIVE, 8, &v);
        }

        if let Some(orig_id) = self.originator_id {
            Self::write_attr(
                &mut buf,
                FLAG_OPTIONAL,
                9,
                &u32::from(orig_id).to_be_bytes(),
            );
        }

        if !self.cluster_list.is_empty() {
            let mut v = BytesMut::new();
            for ip in &self.cluster_list {
                v.put_u32(u32::from(*ip));
            }
            Self::write_attr(&mut buf, FLAG_OPTIONAL, 10, &v);
        }

        // Pass through unknown attributes
        for attr in &self.unknown {
            Self::write_attr(&mut buf, attr.flags, attr.type_code, &attr.value);
        }

        buf
    }

    /// AS_PATH length in number of ASNs (for best-path selection).
    /// AS_SETs count as 1.
    pub fn as_path_len(&self) -> usize {
        self.as_path
            .iter()
            .map(|seg| match seg {
                AsPathSegment::AsSet(_) => 1,
                AsPathSegment::AsSequence(v) => v.len(),
            })
            .sum()
    }

    fn write_attr(buf: &mut BytesMut, flags: u8, type_code: u8, value: &[u8]) {
        let len = value.len();
        if len > 255 {
            buf.put_u8(flags | FLAG_EXTENDED_LEN);
            buf.put_u8(type_code);
            buf.put_u16(len as u16);
        } else {
            buf.put_u8(flags);
            buf.put_u8(type_code);
            buf.put_u8(len as u8);
        }
        buf.put_slice(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn roundtrip(attrs: &PathAttributes) -> PathAttributes {
        let serialized = attrs.serialize();
        PathAttributes::parse(Bytes::from(serialized)).unwrap()
    }

    #[test]
    fn test_origin_roundtrip() {
        let attrs = PathAttributes {
            origin: Some(Origin::Igp),
            ..Default::default()
        };
        let parsed = roundtrip(&attrs);
        assert_eq!(parsed.origin, Some(Origin::Igp));
    }

    #[test]
    fn test_as_path_roundtrip() {
        let attrs = PathAttributes {
            as_path: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
            ..Default::default()
        };
        let parsed = roundtrip(&attrs);
        assert_eq!(parsed.as_path.len(), 1);
        assert_eq!(parsed.as_path[0].as_numbers(), &[65001, 65002, 65003]);
        assert_eq!(parsed.as_path_len(), 3);
    }

    #[test]
    fn test_next_hop_roundtrip() {
        let attrs = PathAttributes {
            next_hop: Some(Ipv4Addr::new(192, 0, 2, 1)),
            ..Default::default()
        };
        let parsed = roundtrip(&attrs);
        assert_eq!(parsed.next_hop, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn test_med_local_pref() {
        let attrs = PathAttributes {
            multi_exit_disc: Some(100),
            local_pref: Some(200),
            ..Default::default()
        };
        let parsed = roundtrip(&attrs);
        assert_eq!(parsed.multi_exit_disc, Some(100));
        assert_eq!(parsed.local_pref, Some(200));
    }

    #[test]
    fn test_communities() {
        let attrs = PathAttributes {
            communities: vec![Community(0x00010002), Community::NO_EXPORT],
            ..Default::default()
        };
        let parsed = roundtrip(&attrs);
        assert_eq!(parsed.communities.len(), 2);
        assert_eq!(parsed.communities[1], Community::NO_EXPORT);
        assert_eq!(parsed.communities[0].asn(), 1);
        assert_eq!(parsed.communities[0].value(), 2);
    }

    #[test]
    fn test_full_attributes() {
        let attrs = PathAttributes {
            origin: Some(Origin::Egp),
            as_path: vec![
                AsPathSegment::AsSequence(vec![65000, 65001]),
                AsPathSegment::AsSet(vec![65002, 65003]),
            ],
            next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
            multi_exit_disc: Some(50),
            local_pref: Some(100),
            atomic_aggregate: true,
            communities: vec![Community::NO_EXPORT],
            ..Default::default()
        };
        let parsed = roundtrip(&attrs);
        assert_eq!(parsed.origin, Some(Origin::Egp));
        assert_eq!(parsed.as_path.len(), 2);
        assert_eq!(parsed.as_path_len(), 3); // 2 AS_SEQ + 1 AS_SET
        assert!(parsed.atomic_aggregate);
        assert_eq!(parsed.communities[0], Community::NO_EXPORT);
    }
}
