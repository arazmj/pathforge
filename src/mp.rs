use bytes::{Buf, BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Address Family Identifiers (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

impl TryFrom<u16> for Afi {
    type Error = MpError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Afi::Ipv4),
            2 => Ok(Afi::Ipv6),
            _ => Err(MpError::UnknownAfi(v)),
        }
    }
}

/// Subsequent Address Family Identifiers (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    LabeledUnicast = 4,
}

impl TryFrom<u8> for Safi {
    type Error = MpError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Safi::Unicast),
            2 => Ok(Safi::Multicast),
            4 => Ok(Safi::LabeledUnicast),
            _ => Err(MpError::UnknownSafi(v)),
        }
    }
}

#[derive(Debug, Error)]
pub enum MpError {
    #[error("Unknown AFI: {0}")]
    UnknownAfi(u16),
    #[error("Unknown SAFI: {0}")]
    UnknownSafi(u8),
    #[error("Buffer too short")]
    TooShort,
    #[error("Invalid address for AFI")]
    InvalidAddress,
}

/// An IP network prefix for multi-protocol use (IPv4 or IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpPrefix {
    pub afi: Afi,
    pub prefix_len: u8,
    pub address: IpAddr,
}

impl MpPrefix {
    pub fn ipv4(addr: Ipv4Addr, len: u8) -> Self {
        Self {
            afi: Afi::Ipv4,
            prefix_len: len,
            address: IpAddr::V4(addr),
        }
    }

    pub fn ipv6(addr: Ipv6Addr, len: u8) -> Self {
        Self {
            afi: Afi::Ipv6,
            prefix_len: len,
            address: IpAddr::V6(addr),
        }
    }

    pub fn encoded_len(&self) -> usize {
        (self.prefix_len as usize).div_ceil(8)
    }

    pub fn parse(buf: &mut impl Buf, afi: Afi) -> Result<Self, MpError> {
        if buf.remaining() < 1 {
            return Err(MpError::TooShort);
        }
        let prefix_len = buf.get_u8();
        let byte_len = (prefix_len as usize).div_ceil(8);
        if buf.remaining() < byte_len {
            return Err(MpError::TooShort);
        }
        let address = match afi {
            Afi::Ipv4 => {
                let mut b = [0u8; 4];
                b.iter_mut().take(byte_len).for_each(|x| *x = buf.get_u8());
                IpAddr::V4(Ipv4Addr::from(b))
            }
            Afi::Ipv6 => {
                let mut b = [0u8; 16];
                b.iter_mut().take(byte_len).for_each(|x| *x = buf.get_u8());
                IpAddr::V6(Ipv6Addr::from(b))
            }
        };
        Ok(Self {
            afi,
            prefix_len,
            address,
        })
    }

    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u8(self.prefix_len);
        let byte_len = self.encoded_len();
        match self.address {
            IpAddr::V4(a) => buf.put_slice(&a.octets()[..byte_len]),
            IpAddr::V6(a) => buf.put_slice(&a.octets()[..byte_len]),
        }
    }
}

impl std::fmt::Display for MpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// BGP MP_REACH_NLRI attribute (RFC 4760 §3).
///
/// Announces reachable multi-protocol destinations.
#[derive(Debug, Clone)]
pub struct MpReachNlri {
    pub afi: Afi,
    pub safi: Safi,
    /// Next hop address(es).
    pub next_hops: Vec<IpAddr>,
    /// Reachable NLRI prefixes.
    pub nlri: Vec<MpPrefix>,
}

impl MpReachNlri {
    pub fn new(afi: Afi, safi: Safi, next_hop: IpAddr) -> Self {
        Self {
            afi,
            safi,
            next_hops: vec![next_hop],
            nlri: vec![],
        }
    }

    /// Parse MP_REACH_NLRI attribute value.
    pub fn parse(mut buf: impl Buf) -> Result<Self, MpError> {
        if buf.remaining() < 4 {
            return Err(MpError::TooShort);
        }
        let afi = Afi::try_from(buf.get_u16())?;
        let safi = Safi::try_from(buf.get_u8())?;
        let nh_len = buf.get_u8() as usize;
        if buf.remaining() < nh_len {
            return Err(MpError::TooShort);
        }

        let mut next_hops = vec![];
        let nh_bytes = buf.copy_to_bytes(nh_len);
        let mut nh_buf = nh_bytes.clone();
        match afi {
            Afi::Ipv4 => {
                while nh_buf.remaining() >= 4 {
                    next_hops.push(IpAddr::V4(Ipv4Addr::from(nh_buf.get_u32())));
                }
            }
            Afi::Ipv6 => {
                while nh_buf.remaining() >= 16 {
                    let mut b = [0u8; 16];
                    nh_buf.copy_to_slice(&mut b);
                    next_hops.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
            }
        }

        let _snpa = buf.get_u8(); // SNPA (must be 0)
        let mut nlri = vec![];
        while buf.remaining() > 0 {
            nlri.push(MpPrefix::parse(&mut buf, afi)?);
        }
        Ok(Self {
            afi,
            safi,
            next_hops,
            nlri,
        })
    }

    /// Serialize MP_REACH_NLRI as raw attribute bytes (without outer flags/type/len).
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u16(self.afi as u16);
        buf.put_u8(self.safi as u8);

        // Next hop
        let mut nh_buf = BytesMut::new();
        for nh in &self.next_hops {
            match nh {
                IpAddr::V4(a) => nh_buf.put_slice(&a.octets()),
                IpAddr::V6(a) => nh_buf.put_slice(&a.octets()),
            }
        }
        buf.put_u8(nh_buf.len() as u8);
        buf.put(nh_buf);
        buf.put_u8(0); // SNPA count = 0

        for prefix in &self.nlri {
            prefix.serialize(&mut buf);
        }
        buf
    }
}

/// BGP MP_UNREACH_NLRI attribute (RFC 4760 §4).
///
/// Withdraws multi-protocol destinations.
#[derive(Debug, Clone)]
pub struct MpUnreachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn: Vec<MpPrefix>,
}

impl MpUnreachNlri {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self {
            afi,
            safi,
            withdrawn: vec![],
        }
    }

    pub fn parse(mut buf: impl Buf) -> Result<Self, MpError> {
        if buf.remaining() < 3 {
            return Err(MpError::TooShort);
        }
        let afi = Afi::try_from(buf.get_u16())?;
        let safi = Safi::try_from(buf.get_u8())?;
        let mut withdrawn = vec![];
        while buf.remaining() > 0 {
            withdrawn.push(MpPrefix::parse(&mut buf, afi)?);
        }
        Ok(Self {
            afi,
            safi,
            withdrawn,
        })
    }

    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u16(self.afi as u16);
        buf.put_u8(self.safi as u8);
        for prefix in &self.withdrawn {
            prefix.serialize(&mut buf);
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_mp_prefix_ipv4_roundtrip() {
        let p = MpPrefix::ipv4(Ipv4Addr::new(10, 0, 0, 0), 8);
        let mut buf = BytesMut::new();
        p.serialize(&mut buf);
        let parsed = MpPrefix::parse(&mut buf, Afi::Ipv4).unwrap();
        assert_eq!(parsed.prefix_len, 8);
        assert_eq!(parsed.address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn test_mp_prefix_ipv6_roundtrip() {
        let addr: Ipv6Addr = "2001:db8::".parse().unwrap();
        let p = MpPrefix::ipv6(addr, 32);
        let mut buf = BytesMut::new();
        p.serialize(&mut buf);
        let parsed = MpPrefix::parse(&mut buf, Afi::Ipv6).unwrap();
        assert_eq!(parsed.prefix_len, 32);
        assert_eq!(parsed.address, IpAddr::V6(addr));
    }

    #[test]
    fn test_mp_reach_nlri_roundtrip() {
        let nh: IpAddr = "2001:db8::1".parse().unwrap();
        let mut reach = MpReachNlri::new(Afi::Ipv6, Safi::Unicast, nh);
        reach
            .nlri
            .push(MpPrefix::ipv6("2001:db8:1::".parse().unwrap(), 48));
        reach
            .nlri
            .push(MpPrefix::ipv6("fd00::".parse().unwrap(), 8));

        let serialized = reach.serialize();
        let parsed = MpReachNlri::parse(Bytes::from(serialized)).unwrap();
        assert_eq!(parsed.afi, Afi::Ipv6);
        assert_eq!(parsed.safi, Safi::Unicast);
        assert_eq!(parsed.next_hops.len(), 1);
        assert_eq!(parsed.nlri.len(), 2);
        assert_eq!(parsed.nlri[0].prefix_len, 48);
    }

    #[test]
    fn test_mp_unreach_nlri_roundtrip() {
        let mut unreach = MpUnreachNlri::new(Afi::Ipv6, Safi::Unicast);
        unreach
            .withdrawn
            .push(MpPrefix::ipv6("2001:db8::".parse().unwrap(), 32));
        let serialized = unreach.serialize();
        let parsed = MpUnreachNlri::parse(Bytes::from(serialized)).unwrap();
        assert_eq!(parsed.afi, Afi::Ipv6);
        assert_eq!(parsed.withdrawn.len(), 1);
        assert_eq!(parsed.withdrawn[0].prefix_len, 32);
    }

    #[test]
    fn test_mp_reach_ipv4_roundtrip() {
        let nh: IpAddr = "10.0.0.1".parse().unwrap();
        let mut reach = MpReachNlri::new(Afi::Ipv4, Safi::Unicast, nh);
        reach
            .nlri
            .push(MpPrefix::ipv4(Ipv4Addr::new(192, 168, 0, 0), 24));
        let serialized = reach.serialize();
        let parsed = MpReachNlri::parse(Bytes::from(serialized)).unwrap();
        assert_eq!(parsed.afi, Afi::Ipv4);
        assert_eq!(parsed.nlri[0].prefix_len, 24);
    }
}
