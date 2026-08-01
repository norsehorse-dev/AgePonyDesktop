#![no_main]
//! Identity file parsing: reached by any file the user picks as an identity,
//! including files that are not identity files at all.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = agepony_core::identity::parse_identities(s);
        let _ = agepony_core::store::describe_identity_text(s);
    }
    let _ = agepony_core::identity::looks_encrypted(data);
});
