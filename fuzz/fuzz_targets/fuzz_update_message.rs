#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use pathforge::message::update::UpdateMessage;

// Fuzz the UPDATE message parser: withdrawn routes, path attributes, NLRI.
// UPDATE parsing is the most complex message type and most likely to be seen
// from untrusted peers in a production deployment.
fuzz_target!(|data: &[u8]| {
    let _ = UpdateMessage::parse(Bytes::copy_from_slice(data));
});
