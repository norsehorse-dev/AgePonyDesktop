#![no_main]
//! The hand-rolled Bech32 decoder.
//!
//! The highest-risk parser in the crate: it exists only because the `bech32`
//! crate enforces a 90-character limit that a post-quantum recipient blows
//! past, so nobody outside this project has ever reviewed it. It sees every
//! recipient and identity string a user pastes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic, and must never claim success on input it cannot
        // reproduce.
        if let Ok((hrp, bytes)) = agepony_core::pq::bech32::decode(s) {
            if let Ok(re) = agepony_core::pq::bech32::encode(&hrp, &bytes) {
                assert_eq!(
                    re.to_lowercase(),
                    s.to_lowercase(),
                    "decode accepted a string it cannot round trip"
                );
            }
        }
    }
});
