#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use pathforge::message::open::OpenMessage;

// Fuzz the OPEN message parser (version, AS, hold time, router-id, optional params).
fuzz_target!(|data: &[u8]| {
    let _ = OpenMessage::parse(Bytes::copy_from_slice(data));
});
