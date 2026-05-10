#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use pathforge::attr::PathAttributes;

// Fuzz BGP path attribute parsing (ORIGIN, AS_PATH, NEXT_HOP, MED, communities…).
// Covers the attribute wire format which is the most complex parsing surface.
fuzz_target!(|data: &[u8]| {
    let _ = PathAttributes::parse(Bytes::copy_from_slice(data));
});
