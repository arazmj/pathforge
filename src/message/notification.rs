use super::{Header, MessageError, MessageType, HEADER_LEN};
use bytes::{Buf, BufMut, BytesMut};

/// BGP NOTIFICATION error codes (RFC 4271 §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Cease = 6,
}

/// BGP NOTIFICATION message (RFC 4271 §4.5).
///
/// Sent when an error condition is detected. After sending, the session is closed.
#[derive(Debug, Clone)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

impl NotificationMessage {
    pub fn new(error_code: ErrorCode, error_subcode: u8) -> Self {
        Self {
            error_code: error_code as u8,
            error_subcode,
            data: vec![],
        }
    }

    pub fn cease() -> Self {
        Self::new(ErrorCode::Cease, 0)
    }

    pub fn hold_timer_expired() -> Self {
        Self::new(ErrorCode::HoldTimerExpired, 0)
    }

    /// Parse NOTIFICATION body (excluding header).
    pub fn parse(mut body: impl Buf) -> Result<Self, MessageError> {
        if body.remaining() < 2 {
            return Err(MessageError::TooShort {
                expected: 2,
                got: body.remaining(),
            });
        }
        let error_code = body.get_u8();
        let error_subcode = body.get_u8();
        let mut data = vec![0u8; body.remaining()];
        body.copy_to_slice(&mut data);
        Ok(Self {
            error_code,
            error_subcode,
            data,
        })
    }

    /// Serialize NOTIFICATION message (header + body).
    pub fn serialize(&self) -> BytesMut {
        let body_len = 2 + self.data.len();
        let hdr = Header::new(MessageType::Notification, body_len);
        let mut out = BytesMut::with_capacity(HEADER_LEN + body_len);
        hdr.serialize(&mut out);
        out.put_u8(self.error_code);
        out.put_u8(self.error_subcode);
        out.put_slice(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_roundtrip() {
        let orig = NotificationMessage::new(ErrorCode::HoldTimerExpired, 0);
        let serialized = orig.serialize();
        let body = serialized.freeze().slice(HEADER_LEN..);
        let parsed = NotificationMessage::parse(body).unwrap();
        assert_eq!(parsed.error_code, ErrorCode::HoldTimerExpired as u8);
        assert_eq!(parsed.error_subcode, 0);
    }

    #[test]
    fn test_cease_notification() {
        let msg = NotificationMessage::cease();
        let serialized = msg.serialize();
        assert_eq!(serialized.len(), HEADER_LEN + 2);
    }
}
