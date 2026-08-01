#![no_main]
//! Whole age files, in memory.
//!
//! Header parsing is the `age` crate's job, but our wrappers sit around it and
//! must not panic on a malformed file — `panic = "abort"` in release means a
//! panic takes the process down, so a bad file would close the app.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let identity = agepony_core::identity::generate_x25519();
    let identities: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(identity)];
    let _ = agepony_core::decrypt::decrypt_to_memory(data, &identities);
    let _ = agepony_core::porting::open_bytes(data, &identities);
});
