#![no_main]
//! The recipient book is JSON in the config directory and a user can edit it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(book) = serde_json::from_str::<agepony_core::book::Book>(s) {
            let _ = book.search("a");
            let _ = book.sorted();
        }
    }
});
