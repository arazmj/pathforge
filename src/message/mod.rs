use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

pub mod keepalive;
pub mod notification;
pub mod open;
pub mod route_refresh;
pub mod update;

/// BGP message type codes (RFC 4271 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl TryFrom<u8> for MessageType {
    type Error = MessageError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(MessageType::Open),
            2 => Ok(MessageType::Update),
            3 => Ok(MessageType::Notification),
            4 => Ok(MessageType::Keepalive),
            5 => Ok(MessageType::RouteRefresh),
            _ => Err(MessageError::UnknownType(v)),
        }
    }
}

/// BGP message errors.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Unknown BGP message type: {0}")]
    UnknownType(u8),
    #[error("Message too short: expected at least {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("Invalid marker: expected all 0xFF")]
    InvalidMarker,
    #[error("Invalid message length: {0}")]
    InvalidLength(u16),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// BGP message header (19 bytes): 16-byte marker + 2-byte length + 1-byte type.
/// RFC 4271 §4.1
#[derive(Debug, Clone)]
pub struct Header {
    pub length: u16,
    pub msg_type: MessageType,
}

pub const MARKER: [u8; 16] = [0xFF; 16];
pub const HEADER_LEN: usize = 19;
pub const MAX_MESSAGE_LEN: usize = 4096;

impl Header {
    pub fn new(msg_type: MessageType, body_len: usize) -> Self {
        Self {
            length: (HEADER_LEN + body_len) as u16,
            msg_type,
        }
    }

    /// Parse a BGP header from a buffer of at least 19 bytes.
    pub fn parse(buf: &mut impl Buf) -> Result<Self, MessageError> {
        if buf.remaining() < HEADER_LEN {
            return Err(MessageError::TooShort {
                expected: HEADER_LEN,
                got: buf.remaining(),
            });
        }
        let mut marker = [0u8; 16];
        buf.copy_to_slice(&mut marker);
        if marker != MARKER {
            return Err(MessageError::InvalidMarker);
        }
        let length = buf.get_u16();
        if (length as usize) < HEADER_LEN || (length as usize) > MAX_MESSAGE_LEN {
            return Err(MessageError::InvalidLength(length));
        }
        let type_byte = buf.get_u8();
        let msg_type = MessageType::try_from(type_byte)?;
        Ok(Self { length, msg_type })
    }

    /// Serialize the BGP header into a buffer.
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_slice(&MARKER);
        buf.put_u16(self.length);
        buf.put_u8(self.msg_type as u8);
    }
}

/// A complete BGP message (header + body bytes).
#[derive(Debug, Clone)]
pub struct BgpMessage {
    pub header: Header,
    pub body: Bytes,
}

impl BgpMessage {
    /// Read a complete BGP message from a byte buffer.
    pub fn parse(buf: &mut BytesMut) -> Result<Option<Self>, MessageError> {
        if buf.len() < HEADER_LEN {
            return Ok(None); // Need more data
        }
        let mut peek = buf.as_ref();
        let header = Header::parse(&mut peek)?;
        let total = header.length as usize;
        if buf.len() < total {
            return Ok(None); // Need more data
        }
        // Consume full message
        buf.advance(HEADER_LEN);
        let body = buf.copy_to_bytes(total - HEADER_LEN);
        Ok(Some(BgpMessage { header, body }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let hdr = Header::new(MessageType::Keepalive, 0);
        let mut buf = BytesMut::new();
        hdr.serialize(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN);
        let parsed = Header::parse(&mut buf).unwrap();
        assert_eq!(parsed.msg_type, MessageType::Keepalive);
        assert_eq!(parsed.length, HEADER_LEN as u16);
    }

    #[test]
    fn test_invalid_marker() {
        let mut buf = BytesMut::from(&[0u8; 19][..]);
        assert!(matches!(
            Header::parse(&mut buf),
            Err(MessageError::InvalidMarker)
        ));
    }
}
