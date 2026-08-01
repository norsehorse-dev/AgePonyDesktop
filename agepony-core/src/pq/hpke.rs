//! HPKE (RFC 9180) base mode, single shot, for exactly one cipher suite.
//!
//! KEM `0x647a` (MLKEM768-X25519), KDF HKDF-SHA256 (`0x0001`), AEAD
//! ChaCha20Poly1305 (`0x0003`).
//!
//! This is deliberately not a general HPKE implementation. There is one mode
//! (base), one suite, one message, and sequence number zero, because that is
//! all age's `mlkem768x25519` recipient uses. Fewer moving parts, fewer ways to
//! be subtly wrong.

use crate::error::{CoreError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// KEM identifier for MLKEM768-X25519.
pub const KEM_ID: u16 = 0x647a;
/// KDF identifier for HKDF-SHA256.
pub const KDF_ID: u16 = 0x0001;
/// AEAD identifier for ChaCha20Poly1305.
pub const AEAD_ID: u16 = 0x0003;

/// AEAD key length.
const NK: usize = 32;
/// AEAD nonce length.
const NN: usize = 12;
/// HPKE base mode.
const MODE_BASE: u8 = 0x00;

const VERSION: &[u8] = b"HPKE-v1";

/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
fn suite_id() -> [u8; 10] {
    let mut out = [0_u8; 10];
    out[..4].copy_from_slice(b"HPKE");
    out[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    out[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    out[8..10].copy_from_slice(&AEAD_ID.to_be_bytes());
    out
}

/// `LabeledExtract(salt, label, ikm)` from RFC 9180 §4.
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled_ikm = Vec::with_capacity(VERSION.len() + 10 + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(VERSION);
    labeled_ikm.extend_from_slice(&suite_id());
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(&prk);
    out
}

/// `LabeledExpand(prk, label, info, L)` from RFC 9180 §4.
fn labeled_expand(prk: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) -> Result<()> {
    let len = u16::try_from(out.len())
        .map_err(|_| CoreError::BareIo(std::io::Error::other("hpke expand length overflow")))?;

    let mut info = Vec::with_capacity(2 + VERSION.len() + 10 + label.len() + context.len());
    info.extend_from_slice(&len.to_be_bytes());
    info.extend_from_slice(VERSION);
    info.extend_from_slice(&suite_id());
    info.extend_from_slice(label);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| CoreError::BareIo(std::io::Error::other("hpke prk rejected")))?;
    hk.expand(&info, out)
        .map_err(|_| CoreError::BareIo(std::io::Error::other("hpke expand failed")))
}

/// The base-mode key schedule. Returns the AEAD key and base nonce.
fn key_schedule(shared_secret: &[u8], info: &[u8]) -> Result<(Zeroizing<[u8; NK]>, [u8; NN])> {
    // psk and psk_id are empty in base mode.
    let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], b"info_hash", info);

    let mut context = Vec::with_capacity(1 + 32 + 32);
    context.push(MODE_BASE);
    context.extend_from_slice(psk_id_hash.as_ref());
    context.extend_from_slice(info_hash.as_ref());

    let secret = labeled_extract(shared_secret, b"secret", &[]);

    let mut key = Zeroizing::new([0_u8; NK]);
    labeled_expand(&secret, b"key", &context, key.as_mut())?;
    let mut base_nonce = [0_u8; NN];
    labeled_expand(&secret, b"base_nonce", &context, &mut base_nonce)?;

    Ok((key, base_nonce))
}

/// Seal `plaintext` under a shared secret. Sequence number zero, empty aad.
///
/// # Errors
///
/// [`CoreError::BareIo`] if the key schedule or the AEAD rejects its inputs,
/// which for well-formed inputs cannot happen.
pub fn seal(shared_secret: &[u8], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = key_schedule(shared_secret, info)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(
        *<Zeroizing<[u8; NK]> as core::ops::Deref>::deref(&key),
    ));
    cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| CoreError::BareIo(std::io::Error::other("hpke seal failed")))
}

/// Open a sealed message. Returns `None` if authentication fails, which is the
/// normal outcome for a stanza that belongs to someone else.
///
/// # Errors
///
/// [`CoreError::BareIo`] if the key schedule itself fails. A failed
/// authentication is `Ok(None)`, not an error.
pub fn open(
    shared_secret: &[u8],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let (key, nonce) = key_schedule(shared_secret, info)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(
        *<Zeroizing<[u8; NK]> as core::ops::Deref>::deref(&key),
    ));
    Ok(cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .ok()
        .map(Zeroizing::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &[u8] = b"age-encryption.org/mlkem768x25519";

    #[test]
    fn seal_then_open_round_trips() {
        let ss = [7_u8; 32];
        let sealed = seal(&ss, INFO, b"sixteen byte key").expect("seal");
        assert_eq!(sealed.len(), 16 + 16);
        let opened = open(&ss, INFO, &sealed)
            .expect("open")
            .expect("authenticates");
        assert_eq!(opened.as_slice(), b"sixteen byte key");
    }

    #[test]
    fn a_wrong_shared_secret_fails_to_authenticate() {
        let sealed = seal(&[7_u8; 32], INFO, b"sixteen byte key").expect("seal");
        assert!(
            open(&[8_u8; 32], INFO, &sealed)
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn a_different_info_string_fails_to_authenticate() {
        let ss = [7_u8; 32];
        let sealed = seal(&ss, INFO, b"sixteen byte key").expect("seal");
        assert!(
            open(&ss, b"some other info", &sealed)
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn a_flipped_ciphertext_byte_fails_to_authenticate() {
        let ss = [7_u8; 32];
        let mut sealed = seal(&ss, INFO, b"sixteen byte key").expect("seal");
        sealed[0] ^= 0x01;
        assert!(open(&ss, INFO, &sealed).expect("no error").is_none());
    }

    #[test]
    fn the_suite_id_matches_the_specification() {
        assert_eq!(suite_id(), *b"HPKE\x64\x7a\x00\x01\x00\x03");
    }
}
