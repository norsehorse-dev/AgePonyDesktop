#![no_main]
//! The post-quantum primitives, fed attacker-controlled bytes.
//!
//! `decapsulate` in particular is reached with whatever the stanza carried, on
//! every attempt to decrypt a file with an `mlkem768x25519` recipient.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = agepony_core::pq::xwing::PublicKey::from_bytes(data);

    if data.len() >= 32 {
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&data[..32]);
        let key = agepony_core::pq::xwing::PrivateKey::from_seed(&seed);
        let _ = key.decapsulate(&data[32..]);
        let _ = agepony_core::pq::hpke::open(&seed, agepony_core::pq::HPKE_INFO, &data[32..]);
    }
});
