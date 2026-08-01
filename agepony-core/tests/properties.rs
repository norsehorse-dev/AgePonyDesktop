#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Property tests: what must hold for *any* input, not just the ones we thought of.
//!
//! The known-answer tests prove this crate produces the right bytes for valid
//! input. They say nothing about what it does when handed garbage — and once
//! the app is downloadable, garbage is exactly what it will be handed. Every
//! parser here reaches untrusted bytes: a pasted recipient, a chosen identity
//! file, a `.age` file from a stranger.
//!
//! The bar for all of them is the same and it is low on purpose: **never panic**.
//! A panic in release aborts the process (`panic = "abort"`), so a malformed
//! file would take the whole app down. Returning an error is fine. Returning
//! the wrong answer is not, and a few tests check that too.

use agepony_core::pq;
use proptest::prelude::*;

// ------------------------------------------------------------- Bech32 ---
//
// The highest-risk hand-written code in the crate. It exists because the
// `bech32` crate enforces a 90-character limit that a post-quantum recipient
// blows past, so this parser is ours and nobody else has reviewed it.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Decoding must survive absolutely anything.
    #[test]
    fn bech32_decode_never_panics(s in ".*") {
        let _ = pq::bech32::decode(&s);
    }

    /// Including strings shaped like real ones, which random text never is.
    #[test]
    fn bech32_decode_never_panics_on_plausible_input(
        hrp in "[a-z]{0,12}",
        sep in prop::option::of(Just('1')),
        body in "[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{0,200}",
    ) {
        let s = format!("{hrp}{}{body}", sep.map(String::from).unwrap_or_default());
        let _ = pq::bech32::decode(&s);
    }

    /// Round trip: anything encoded decodes back to itself.
    #[test]
    fn bech32_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..1400)) {
        let encoded = pq::bech32::encode("age1pq", &bytes).expect("encode");
        let (hrp, back) = pq::bech32::decode(&encoded).expect("decode our own output");
        prop_assert_eq!(hrp, "age1pq");
        prop_assert_eq!(back, bytes);
    }

    /// And survives being uppercased, which is what the QR code does.
    #[test]
    fn bech32_survives_case_folding(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        let encoded = pq::bech32::encode("age1pq", &bytes).expect("encode");
        let (_, back) = pq::bech32::decode(&encoded.to_uppercase()).expect("decode uppercase");
        prop_assert_eq!(back, bytes);
    }

    /// The checksum has to earn its place: any single character substitution
    /// must be rejected. This is the property that stops a mistyped recipient
    /// from silently encrypting to the wrong key.
    #[test]
    fn bech32_rejects_any_single_character_error(
        bytes in prop::collection::vec(any::<u8>(), 1..64),
        position in 0_usize..400,
        replacement in 0_usize..32,
    ) {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let encoded = pq::bech32::encode("age1pq", &bytes).expect("encode");
        let mut chars: Vec<u8> = encoded.clone().into_bytes();

        // Only mutate inside the data part, after the separator.
        let start = encoded.rfind('1').expect("separator") + 1;
        if start >= chars.len() {
            return Ok(());
        }
        let at = start + position % (chars.len() - start);
        let new = CHARSET[replacement % CHARSET.len()];
        if chars[at] == new {
            return Ok(());
        }
        chars[at] = new;

        let broken = String::from_utf8(chars).expect("still ascii");
        prop_assert!(
            pq::bech32::decode(&broken).is_err(),
            "a one-character change slipped past the checksum: {encoded} -> {broken}"
        );
    }
}

// -------------------------------------------------- recipients, identities ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn recipient_parse_never_panics(s in ".*") {
        let _ = agepony_core::recipient::parse(&s);
    }

    /// Strings that look like recipients are the interesting ones: they get
    /// past the prefix checks and into the decoders.
    #[test]
    fn recipient_parse_never_panics_on_lookalikes(
        prefix in prop::sample::select(vec!["age1", "age1pq1", "AGE1PQ1", "ssh-ed25519 ", "ssh-rsa "]),
        body in "[a-zA-Z0-9+/=]{0,300}",
    ) {
        let _ = agepony_core::recipient::parse(&format!("{prefix}{body}"));
    }

    #[test]
    fn identity_parsing_never_panics(s in ".*") {
        let _ = agepony_core::identity::parse_identities(&s);
    }

    #[test]
    fn identity_parsing_never_panics_on_lookalikes(
        lines in prop::collection::vec(
            prop_oneof![
                Just("AGE-SECRET-KEY-1QQQQ".to_owned()),
                Just("AGE-SECRET-KEY-PQ-1QQQQ".to_owned()),
                "# [a-z ]{0,40}",
                "[A-Z0-9-]{0,60}",
            ],
            0..8,
        )
    ) {
        let _ = agepony_core::identity::parse_identities(&lines.join("\n"));
    }

    #[test]
    fn pq_recipient_parsing_never_panics(s in ".*") {
        let _ = pq::Recipient::from_bech32(&s);
        let _ = pq::Identity::from_bech32(&s);
    }
}

// ---------------------------------------------------------- raw crypto ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A hostile 1216-byte blob reaches ML-KEM key parsing directly.
    #[test]
    fn hybrid_public_key_parsing_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..1400)
    ) {
        let _ = pq::xwing::PublicKey::from_bytes(&bytes);
    }

    /// Decapsulation is reached with attacker-chosen bytes on every decrypt of
    /// a file carrying an mlkem768x25519 stanza.
    #[test]
    fn decapsulation_never_panics(
        seed in prop::array::uniform32(any::<u8>()),
        enc in prop::collection::vec(any::<u8>(), 0..1300),
    ) {
        let key = pq::xwing::PrivateKey::from_seed(&seed);
        let _ = key.decapsulate(&enc);
    }

    #[test]
    fn hpke_open_never_panics(
        shared in prop::array::uniform32(any::<u8>()),
        ciphertext in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        let _ = pq::hpke::open(&shared, pq::HPKE_INFO, &ciphertext);
    }

    /// The book is JSON on disk and a user can edit it.
    #[test]
    fn book_deserialisation_never_panics(s in ".*") {
        let _ = serde_json::from_str::<agepony_core::book::Book>(&s);
    }
}

// ------------------------------------------------------------ file paths ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The guard against silently destroying an earlier output.
    #[test]
    fn unique_path_never_returns_something_that_exists(
        name in "[a-zA-Z0-9 ._-]{1,40}"
    ) {
        let dir = std::env::temp_dir().join("agepony-prop-unique");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(&name);
        let chosen = agepony_core::encrypt::unique_path(&path);
        prop_assert!(!chosen.exists(), "{} already exists", chosen.display());

        std::fs::write(&chosen, b"x").expect("write");
        let next = agepony_core::encrypt::unique_path(&path);
        prop_assert!(!next.exists());
        prop_assert_ne!(next, chosen.clone());
        let _ = std::fs::remove_file(&chosen);
    }
}

// ----------------------------------------------------- streaming round trip ---

/// Chunk boundaries are the classic failure mode in streaming AEAD code, so the
/// sizes are drawn to cluster around them rather than uniformly.
fn interesting_size() -> impl Strategy<Value = usize> {
    let chunk = agepony_core::CHUNK;
    prop_oneof![
        Just(0_usize),
        1_usize..64,
        (chunk - 2)..(chunk + 3),
        (2 * chunk - 2)..(2 * chunk + 3),
        0_usize..(3 * chunk),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn encrypt_decrypt_round_trips_at_any_size(size in interesting_size()) {
        let dir = std::env::temp_dir().join("agepony-prop-roundtrip");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let plain = dir.join("p.bin");
        let ct = dir.join("p.bin.age");
        let back = dir.join("p.back");
        for f in [&plain, &ct, &back] {
            let _ = std::fs::remove_file(f);
        }

        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(&plain, &data).expect("write");

        let id = agepony_core::identity::generate_x25519();
        let recipients =
            agepony_core::recipient::parse_all([id.to_public().to_string()]).expect("parse");
        agepony_core::encrypt::encrypt_file(
            &plain, &ct,
            agepony_core::encrypt::To::Recipients(&recipients),
            false, &mut |_| true,
        ).expect("encrypt");

        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];
        agepony_core::decrypt::decrypt_file(
            &ct, &back,
            agepony_core::decrypt::With::Identities(&ids),
            &mut |_| true,
        ).expect("decrypt");

        prop_assert_eq!(std::fs::read(&back).expect("read"), data);
    }

    /// Flip one bit anywhere in a ciphertext: decryption must fail, and must
    /// not leave a partial plaintext behind. The second half is the one that
    /// matters — a truncated, unauthenticated file on disk is worse than an
    /// error.
    #[test]
    fn any_single_bit_flip_is_caught_and_leaves_nothing(
        size in 1_usize..4096,
        bit in 0_usize..8,
        position in 0_usize..10_000,
    ) {
        let dir = std::env::temp_dir().join("agepony-prop-tamper");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let plain = dir.join("t.bin");
        let ct = dir.join("t.bin.age");
        let out = dir.join("t.out");
        for f in [&plain, &ct, &out] {
            let _ = std::fs::remove_file(f);
        }

        std::fs::write(&plain, vec![0xA5_u8; size]).expect("write");
        let id = agepony_core::identity::generate_x25519();
        let recipients =
            agepony_core::recipient::parse_all([id.to_public().to_string()]).expect("parse");
        agepony_core::encrypt::encrypt_file(
            &plain, &ct,
            agepony_core::encrypt::To::Recipients(&recipients),
            false, &mut |_| true,
        ).expect("encrypt");

        let mut bytes = std::fs::read(&ct).expect("read ct");
        let at = position % bytes.len();
        bytes[at] ^= 1 << bit;
        std::fs::write(&ct, &bytes).expect("write tampered");

        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];
        let result = agepony_core::decrypt::decrypt_file(
            &ct, &out,
            agepony_core::decrypt::With::Identities(&ids),
            &mut |_| true,
        );

        prop_assert!(result.is_err(), "a flipped bit at byte {at} was not detected");
        prop_assert!(!out.exists(), "a failed decrypt left {} behind", out.display());
    }
}
