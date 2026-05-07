//! BGP ROUTE-REFRESH message (RFC 2918)

use bytes::{BufMut, BytesMut};

/// BGP ROUTE-REFRESH message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefresh {
    pub afi: u16,
    pub safi: u8,
}

impl RouteRefresh {
    pub fn new(afi: u16, safi: u8) -> Self {
        Self { afi, safi }
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 { return None; }
        Some(Self {
            afi: u16::from_be_bytes([data[0], data[1]]),
            safi: data[3],
        })
    }

    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        // BGP header
        buf.put_bytes(0xFF, 16);          // marker
        buf.put_u16(19 + 4);              // length (header + body)
        buf.put_u8(5);                    // type = ROUTE-REFRESH
        // Body
        buf.put_u16(self.afi);
        buf.put_u8(0);                    // reserved
        buf.put_u8(self.safi);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_refresh_ipv4_unicast() {
        let rr = RouteRefresh::new(1, 1);
        let bytes = rr.serialize().freeze();
        assert_eq!(bytes[18], 5);         // type = ROUTE-REFRESH
        let parsed = RouteRefresh::parse(&bytes[19..]).unwrap();
        assert_eq!(parsed.afi, 1);
        assert_eq!(parsed.safi, 1);
    }

    #[test]
    fn test_route_refresh_ipv6_unicast() {
        let rr = RouteRefresh::new(2, 1);
        let bytes = rr.serialize().freeze();
        let parsed = RouteRefresh::parse(&bytes[19..]).unwrap();
        assert_eq!(parsed, RouteRefresh { afi: 2, safi: 1 });
    }

    #[test]
    fn test_route_refresh_too_short() {
        assert!(RouteRefresh::parse(&[1, 0, 0]).is_none());
    }
}
