use bytes::BytesMut;
use super::{Header, MessageType, HEADER_LEN};

/// BGP KEEPALIVE message (RFC 4271 §4.4).
///
/// Just a 19-byte header with no body. Sent to maintain the session
/// and acknowledge an OPEN message.
#[derive(Debug, Clone, Default)]
pub struct KeepaliveMessage;

impl KeepaliveMessage {
    /// Serialize KEEPALIVE (header only, no body).
    pub fn serialize(&self) -> BytesMut {
        let hdr = Header::new(MessageType::Keepalive, 0);
        let mut out = BytesMut::with_capacity(HEADER_LEN);
        hdr.serialize(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Header, MessageType};

    #[test]
    fn test_keepalive_serialize() {
        let msg = KeepaliveMessage;
        let bytes = msg.serialize();
        assert_eq!(bytes.len(), HEADER_LEN);
        // Verify it can be parsed back
        let mut buf = bytes;
        let hdr = Header::parse(&mut buf).unwrap();
        assert_eq!(hdr.msg_type, MessageType::Keepalive);
        assert_eq!(hdr.length, HEADER_LEN as u16);
    }
}
