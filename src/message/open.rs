use bytes::{Buf, BufMut, BytesMut};
use std::net::Ipv4Addr;

use super::{Header, MessageError, MessageType, HEADER_LEN};

/// BGP OPEN message (RFC 4271 §4.2).
///
/// Sent after TCP connection is established to negotiate session parameters.
#[derive(Debug, Clone)]
pub struct OpenMessage {
    /// BGP version (must be 4).
    pub version: u8,
    /// The AS number of the sender.
    pub my_as: u16,
    /// Proposed hold time in seconds (0 or ≥3).
    pub hold_time: u16,
    /// BGP Identifier (router ID) of the sender.
    pub bgp_id: Ipv4Addr,
    /// Optional parameters (capabilities etc.).
    pub optional_params: Vec<OptionalParam>,
}

/// BGP OPEN optional parameter.
#[derive(Debug, Clone)]
pub struct OptionalParam {
    pub param_type: u8,
    pub value: Vec<u8>,
}

impl OpenMessage {
    pub fn new(my_as: u16, hold_time: u16, bgp_id: Ipv4Addr) -> Self {
        Self {
            version: 4,
            my_as,
            hold_time,
            bgp_id,
            optional_params: vec![],
        }
    }

    /// Parse OPEN message body (excluding header).
    pub fn parse(mut body: impl Buf) -> Result<Self, MessageError> {
        if body.remaining() < 10 {
            return Err(MessageError::TooShort { expected: 10, got: body.remaining() });
        }
        let version = body.get_u8();
        let my_as = body.get_u16();
        let hold_time = body.get_u16();
        let bgp_id = Ipv4Addr::from(body.get_u32());
        let opt_param_len = body.get_u8() as usize;

        if body.remaining() < opt_param_len {
            return Err(MessageError::TooShort { expected: opt_param_len, got: body.remaining() });
        }

        let mut optional_params = vec![];
        let mut remaining = opt_param_len;
        while remaining >= 2 {
            let param_type = body.get_u8();
            let param_len = body.get_u8() as usize;
            remaining -= 2;
            if body.remaining() < param_len || remaining < param_len {
                return Err(MessageError::Parse("Truncated optional parameter".into()));
            }
            let mut value = vec![0u8; param_len];
            body.copy_to_slice(&mut value);
            remaining -= param_len;
            optional_params.push(OptionalParam { param_type, value });
        }

        Ok(Self { version, my_as, hold_time, bgp_id, optional_params })
    }

    /// Serialize OPEN message (header + body).
    pub fn serialize(&self) -> BytesMut {
        let mut body = BytesMut::new();
        body.put_u8(self.version);
        body.put_u16(self.my_as);
        body.put_u16(self.hold_time);
        body.put_u32(u32::from(self.bgp_id));

        let mut opt_buf = BytesMut::new();
        for p in &self.optional_params {
            opt_buf.put_u8(p.param_type);
            opt_buf.put_u8(p.value.len() as u8);
            opt_buf.put_slice(&p.value);
        }
        body.put_u8(opt_buf.len() as u8);
        body.put(opt_buf);

        let hdr = Header::new(MessageType::Open, body.len());
        let mut out = BytesMut::with_capacity(HEADER_LEN + body.len());
        hdr.serialize(&mut out);
        out.put(body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_roundtrip() {
        let orig = OpenMessage::new(65001, 90, Ipv4Addr::new(10, 0, 0, 1));
        let serialized = orig.serialize();
        // Skip the 19-byte header for body parsing
        let body = serialized.freeze().slice(HEADER_LEN..);
        let parsed = OpenMessage::parse(body).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.my_as, 65001);
        assert_eq!(parsed.hold_time, 90);
        assert_eq!(parsed.bgp_id, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_open_with_optional_param() {
        let mut msg = OpenMessage::new(65000, 180, Ipv4Addr::new(1, 1, 1, 1));
        msg.optional_params.push(OptionalParam { param_type: 2, value: vec![1, 4, 0, 1, 0, 1] });
        let serialized = msg.serialize();
        let body = serialized.freeze().slice(HEADER_LEN..);
        let parsed = OpenMessage::parse(body).unwrap();
        assert_eq!(parsed.optional_params.len(), 1);
        assert_eq!(parsed.optional_params[0].param_type, 2);
    }
}
