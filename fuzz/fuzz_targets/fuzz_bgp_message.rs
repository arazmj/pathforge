#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use pathforge::message::BgpMessage;

// Fuzz the BGP framing layer: header parsing + message body extraction.
// A malformed message must never panic or cause UB — it must return Err or None.
fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    // parse() must not panic regardless of input
    let _ = BgpMessage::parse(&mut buf);
});
