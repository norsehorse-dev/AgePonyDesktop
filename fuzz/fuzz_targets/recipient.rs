#![no_main]
//! Recipient parsing: reached by anything pasted into the recipients field or
//! imported from a recipients file.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = agepony_core::recipient::parse(s);
        let _ = agepony_core::recipient::parse_all(s.lines());
    }
});
