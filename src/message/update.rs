use bytes::{Buf, BufMut, BytesMut};
use std::net::Ipv4Addr;

use super::{Header, MessageError, MessageType, HEADER_LEN};
use crate::attr::PathAttributes;

/// A BGP NLRI prefix (network + prefix length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub prefix_len: u8,
    pub address: Ipv4Addr,
}

impl Prefix {
    #[allow(dead_code)]
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
        }
    }

    /// Number of bytes needed to encode the prefix (ceil(prefix_len / 8)).
    #[allow(dead_code)]
    pub fn encoded_len(&self) -> usize {
        (self.prefix_len as usize).div_ceil(8)
    }

    pub fn parse(buf: &mut impl Buf) -> Result<Self, MessageError> {
        if buf.remaining() < 1 {
            return Err(MessageError::TooShort {
                expected: 1,
                got: 0,
            });
        }
        let prefix_len = buf.get_u8();
        let byte_len = (prefix_len as usize).div_ceil(8);
        if buf.remaining() < byte_len {
            return Err(MessageError::TooShort {
                expected: byte_len,
                got: buf.remaining(),
            });
        }
        let mut addr_bytes = [0u8; 4];
        addr_bytes
            .iter_mut()
            .take(byte_len)
            .for_each(|b| *b = buf.get_u8());
        Ok(Prefix {
            prefix_len,
            address: Ipv4Addr::from(addr_bytes),
        })
    }

    #[allow(dead_code)]
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u8(self.prefix_len);
        let bytes = self.address.octets();
        let byte_len = self.encoded_len();
        buf.put_slice(&bytes[..byte_len]);
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// BGP UPDATE message (RFC 4271 §4.3).
///
/// Carries routing information: withdrawn routes, path attributes, and NLRI.
#[derive(Debug, Clone)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<Prefix>,
    pub path_attributes: PathAttributes,
    pub nlri: Vec<Prefix>,
}

impl UpdateMessage {
    pub fn new() -> Self {
        Self {
            withdrawn_routes: vec![],
            path_attributes: PathAttributes::default(),
            nlri: vec![],
        }
    }

    /// Parse UPDATE body (excluding header).
    pub fn parse(mut body: impl Buf) -> Result<Self, MessageError> {
        if body.remaining() < 4 {
            return Err(MessageError::TooShort {
                expected: 4,
                got: body.remaining(),
            });
        }

        // Withdrawn routes
        let withdrawn_len = body.get_u16() as usize;
        if body.remaining() < withdrawn_len {
            return Err(MessageError::TooShort {
                expected: withdrawn_len,
                got: body.remaining(),
            });
        }
        let mut withdrawn_buf = body.copy_to_bytes(withdrawn_len);
        let mut withdrawn_routes = vec![];
        while withdrawn_buf.remaining() > 0 {
            withdrawn_routes.push(Prefix::parse(&mut withdrawn_buf)?);
        }

        // Path attributes
        let attr_len = body.get_u16() as usize;
        if body.remaining() < attr_len {
            return Err(MessageError::TooShort {
                expected: attr_len,
                got: body.remaining(),
            });
        }
        let attr_bytes = body.copy_to_bytes(attr_len);
        let path_attributes =
            PathAttributes::parse(attr_bytes).map_err(|e| MessageError::Parse(e.to_string()))?;

        // NLRI (remaining bytes)
        let mut nlri = vec![];
        while body.remaining() > 0 {
            nlri.push(Prefix::parse(&mut body)?);
        }

        Ok(Self {
            withdrawn_routes,
            path_attributes,
            nlri,
        })
    }

    /// Serialize UPDATE message (header + body).
    #[allow(dead_code)]
    pub fn serialize(&self) -> BytesMut {
        let mut withdrawn_buf = BytesMut::new();
        for prefix in &self.withdrawn_routes {
            prefix.serialize(&mut withdrawn_buf);
        }
        let attr_buf = self.path_attributes.serialize();
        let mut nlri_buf = BytesMut::new();
        for prefix in &self.nlri {
            prefix.serialize(&mut nlri_buf);
        }

        let body_len = 2 + withdrawn_buf.len() + 2 + attr_buf.len() + nlri_buf.len();
        let hdr = Header::new(MessageType::Update, body_len);

        let mut out = BytesMut::with_capacity(HEADER_LEN + body_len);
        hdr.serialize(&mut out);
        out.put_u16(withdrawn_buf.len() as u16);
        out.put(withdrawn_buf);
        out.put_u16(attr_buf.len() as u16);
        out.put(attr_buf);
        out.put(nlri_buf);
        out
    }
}

impl Default for UpdateMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AsPathSegment, Origin};

    #[test]
    fn test_prefix_roundtrip() {
        let p = Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let mut buf = BytesMut::new();
        p.serialize(&mut buf);
        assert_eq!(buf.len(), 4); // 1 len byte + 3 addr bytes
        let parsed = Prefix::parse(&mut buf).unwrap();
        assert_eq!(parsed.prefix_len, 24);
        assert_eq!(parsed.address, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_update_empty_roundtrip() {
        let msg = UpdateMessage::new();
        let serialized = msg.serialize();
        let body = serialized.freeze().slice(HEADER_LEN..);
        let parsed = UpdateMessage::parse(body).unwrap();
        assert!(parsed.withdrawn_routes.is_empty());
        assert!(parsed.nlri.is_empty());
    }

    #[test]
    fn test_update_with_attrs_and_nlri() {
        let mut msg = UpdateMessage::new();
        msg.path_attributes.origin = Some(Origin::Igp);
        msg.path_attributes.as_path = vec![AsPathSegment::AsSequence(vec![65000, 65001])];
        msg.path_attributes.next_hop = Some(Ipv4Addr::new(10, 0, 0, 1));
        msg.path_attributes.local_pref = Some(100);
        msg.nlri.push(Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        msg.nlri.push(Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12));
        let serialized = msg.serialize();
        let body = serialized.freeze().slice(HEADER_LEN..);
        let parsed = UpdateMessage::parse(body).unwrap();
        assert_eq!(parsed.nlri.len(), 2);
        assert_eq!(parsed.path_attributes.origin, Some(Origin::Igp));
        assert_eq!(parsed.path_attributes.local_pref, Some(100));
        assert_eq!(parsed.path_attributes.as_path_len(), 2);
    }

    #[test]
    fn test_withdrawn_routes() {
        let mut msg = UpdateMessage::new();
        msg.withdrawn_routes
            .push(Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16));
        let serialized = msg.serialize();
        let body = serialized.freeze().slice(HEADER_LEN..);
        let parsed = UpdateMessage::parse(body).unwrap();
        assert_eq!(parsed.withdrawn_routes.len(), 1);
        assert_eq!(parsed.withdrawn_routes[0].prefix_len, 16);
    }
}
