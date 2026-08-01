//! The standardised post-quantum age recipient: `mlkem768x25519` / `age1pq1…`.
//!
//! # Why this is hand-written
//!
//! The Rust `age` crate does not implement this recipient type. It ships
//! `age::tag` (`p256tag`, `age1tag1…`) and `age::tagpq` (`mlkem768p256tag`,
//! `age1tagpq1…`), which are hardware-key recipient types built on P-256 — a
//! different construction, a different stanza and a different Bech32 prefix.
//! `age::tagpq` is additionally encryption-only: it has no `Identity` impl, so
//! the crate cannot decrypt those stanzas at all.
//!
//! AgePony iOS and Android implement the *standard* type introduced by Go `age`
//! v1.3.0, which is what this module matches:
//!
//! | | here / mobile / Go age 1.3.0 | Rust `age::tagpq` |
//! |---|---|---|
//! | stanza tag | `mlkem768x25519` | `mlkem768p256tag` |
//! | recipient | `age1pq1…` | `age1tagpq1…` |
//! | KEM | ML-KEM-768 + X25519 | ML-KEM-768 + P-256 |
//! | decrypts | yes | no |
//!
//! `age` exposes [`age::Recipient`] and [`age::Identity`] as public traits
//! precisely so third parties can do this, and an implementation here plugs
//! straight into `Encryptor::with_recipients` and `Decryptor::decrypt`.
//!
//! # The construction
//!
//! See [`xwing`] for the KEM and [`hpke`] for the key schedule. In brief:
//! stanza tag `mlkem768x25519`, args `[base64_nopad(enc)]`, body the HPKE seal
//! of the 16-byte file key under the X-Wing shared secret, with
//! `info = "age-encryption.org/mlkem768x25519"` and empty aad.
//!
//! Verified byte for byte against the reference vectors in
//! `vectors/agepony-vectors.json`.

pub mod bech32;
pub mod hpke;
pub mod xwing;

use crate::error::{CoreError, Result};
use age::secrecy::ExposeSecret as _;
use age_core::format::{FileKey, Stanza};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use std::collections::HashSet;
use zeroize::Zeroizing;

/// The age stanza tag for this recipient type.
pub const STANZA_TAG: &str = "mlkem768x25519";

/// The HPKE `info` string.
pub const HPKE_INFO: &[u8] = b"age-encryption.org/mlkem768x25519";

/// Bech32 human-readable part for recipients (`age1pq1…`).
pub const RECIPIENT_HRP: &str = "age1pq";

/// Prefix test for recipient strings: the HRP plus the Bech32 separator, so it
/// cannot be confused with a classical `age1…` recipient.
pub const RECIPIENT_HRP_PREFIX: &str = "age1pq1";

/// Bech32 human-readable part for identities (`AGE-SECRET-KEY-PQ-1…`).
pub const IDENTITY_HRP: &str = "AGE-SECRET-KEY-PQ-";

/// Size of the identity seed, in bytes.
pub const SEED_SIZE: usize = xwing::SEED_SIZE;

/// Size of the hybrid public key: `ek_PQ(1184) ‖ ek_T(32)`.
pub const PUBLIC_KEY_SIZE: usize = xwing::PUBLIC_KEY_SIZE;

/// Size of the encapsulation: `ct_PQ(1088) ‖ ct_T(32)`.
pub const ENC_SIZE: usize = xwing::ENC_SIZE;

/// Size of the stanza body: 16-byte file key plus the 16-byte Poly1305 tag.
pub const BODY_SIZE: usize = 32;

/// The age label marking a stanza set as post-quantum.
///
/// age refuses to combine recipients whose label sets differ. That is what
/// stops a post-quantum file from also carrying a classical recipient and
/// silently dropping to classical security — the weakest recipient sets the bar.
pub const POSTQUANTUM_LABEL: &str = "postquantum";

/// An `age1pq1…` recipient.
#[derive(Clone)]
pub struct Recipient(xwing::PublicKey);

impl Recipient {
    /// Wrap a raw 1216-byte hybrid public key.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidRecipient`] if the length is wrong or the ML-KEM
    /// half is malformed.
    pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
        Ok(Self(xwing::PublicKey::from_bytes(bytes)?))
    }

    /// Parse an `age1pq1…` string.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidRecipient`] for a bad checksum, the wrong HRP, or
    /// the wrong payload length.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, bytes) = bech32::decode(s.trim())?;
        if hrp != RECIPIENT_HRP {
            return Err(CoreError::InvalidRecipient(format!(
                "expected an {RECIPIENT_HRP} recipient, got {hrp}"
            )));
        }
        Self::from_public_key(&bytes)
    }

    /// The raw 1216-byte public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Encoding cannot fail for a fixed, valid HRP and payload.
        match bech32::encode(RECIPIENT_HRP, self.0.as_bytes()) {
            Ok(s) => f.write_str(&s),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

impl std::str::FromStr for Recipient {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_bech32(s)
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> std::result::Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let io = |e: CoreError| age::EncryptError::Io(std::io::Error::other(e.to_string()));

        let (enc, shared) = self.0.encapsulate().map_err(io)?;
        let body = hpke::seal(shared.as_ref(), HPKE_INFO, file_key.expose_secret()).map_err(io)?;

        let stanza = Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![B64.encode(enc)],
            body,
        };

        Ok((vec![stanza], HashSet::from([POSTQUANTUM_LABEL.to_owned()])))
    }
}

/// An `AGE-SECRET-KEY-PQ-1…` identity.
pub struct Identity {
    seed: Zeroizing<[u8; SEED_SIZE]>,
    key: xwing::PrivateKey,
}

impl Identity {
    /// Derive an identity from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidIdentity`] if the seed is the wrong length.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; SEED_SIZE] = seed.try_into().map_err(|_| CoreError::InvalidIdentity)?;
        let key = xwing::PrivateKey::from_seed(&seed);
        Ok(Self {
            seed: Zeroizing::new(seed),
            key,
        })
    }

    /// Generate a fresh identity from OS randomness.
    ///
    /// # Errors
    ///
    /// [`CoreError::BareIo`] if the OS randomness source fails.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0_u8; SEED_SIZE]);
        getrandom::fill(seed.as_mut()).map_err(|e| CoreError::BareIo(std::io::Error::other(e)))?;
        Self::from_seed(seed.as_ref())
    }

    /// Parse an `AGE-SECRET-KEY-PQ-1…` string. Case-insensitive, per BIP-0173.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidIdentity`] for a bad checksum, the wrong HRP, or the
    /// wrong payload length.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, bytes) = bech32::decode(s.trim()).map_err(|_| CoreError::InvalidIdentity)?;
        if !hrp.eq_ignore_ascii_case(IDENTITY_HRP) {
            return Err(CoreError::InvalidIdentity);
        }
        Self::from_seed(&bytes)
    }

    /// The `AGE-SECRET-KEY-PQ-1…` string form, uppercase per age convention.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidIdentity`] only if encoding fails, which cannot
    /// happen for a valid seed.
    pub fn to_bech32(&self) -> Result<Zeroizing<String>> {
        let s = bech32::encode(IDENTITY_HRP, self.seed.as_ref())
            .map_err(|_| CoreError::InvalidIdentity)?;
        Ok(Zeroizing::new(s.to_uppercase()))
    }

    /// The recipient corresponding to this identity.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidRecipient`] only if the derived key is malformed,
    /// which cannot happen.
    pub fn to_public(&self) -> Result<Recipient> {
        Recipient::from_public_key(self.key.public_key())
    }
}

impl age::Identity for Identity {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        // Every `None` below means "not our stanza", which is what lets age try
        // the next identity. Only a stanza that is unmistakably ours and
        // unmistakably broken returns an error.
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let [arg] = stanza.args.as_slice() else {
            return None;
        };
        let enc = B64.decode(arg).ok()?;
        if enc.len() != ENC_SIZE || stanza.body.len() != BODY_SIZE {
            return None;
        }

        let shared = self.key.decapsulate(&enc).ok()?;
        let opened = match hpke::open(shared.as_ref(), HPKE_INFO, &stanza.body) {
            Ok(Some(pt)) => pt,
            // Authentication failed: the stanza is for a different identity.
            Ok(None) => return None,
            Err(e) => {
                return Some(Err(age::DecryptError::Io(std::io::Error::other(
                    e.to_string(),
                ))));
            }
        };

        let bytes: [u8; 16] = opened.as_slice().try_into().ok()?;
        Some(Ok(FileKey::new(Box::new(bytes))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::{Identity as _, Recipient as _};

    fn file_key(byte: u8) -> FileKey {
        FileKey::new(Box::new([byte; 16]))
    }

    #[test]
    fn constants_match_the_reference() {
        assert_eq!(STANZA_TAG, "mlkem768x25519");
        assert_eq!(HPKE_INFO, b"age-encryption.org/mlkem768x25519");
        assert_eq!(PUBLIC_KEY_SIZE, 1184 + 32);
        assert_eq!(ENC_SIZE, 1088 + 32);
        assert_eq!(BODY_SIZE, 16 + 16);
    }

    #[test]
    fn wrap_then_unwrap_recovers_the_file_key() {
        let id = Identity::generate().expect("generate");
        let recipient = id.to_public().expect("public");

        let (stanzas, labels) = recipient.wrap_file_key(&file_key(0x42)).expect("wrap");
        assert_eq!(labels, HashSet::from([POSTQUANTUM_LABEL.to_owned()]));
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, STANZA_TAG);
        assert_eq!(stanzas[0].body.len(), BODY_SIZE);

        let recovered = id
            .unwrap_stanza(&stanzas[0])
            .expect("stanza is ours")
            .expect("unwraps");
        assert_eq!(recovered.expose_secret(), &[0x42_u8; 16]);
    }

    #[test]
    fn a_stanza_for_someone_else_returns_none_not_an_error() {
        // This is the behaviour age relies on to try the next identity.
        let theirs = Identity::generate().expect("generate");
        let mine = Identity::generate().expect("generate");
        let (stanzas, _) = theirs
            .to_public()
            .expect("public")
            .wrap_file_key(&file_key(1))
            .expect("wrap");
        assert!(mine.unwrap_stanza(&stanzas[0]).is_none());
    }

    #[test]
    fn a_foreign_stanza_tag_returns_none() {
        let id = Identity::generate().expect("generate");
        let stanza = Stanza {
            tag: "X25519".to_owned(),
            args: vec![B64.encode([0_u8; 32])],
            body: vec![0; 32],
        };
        assert!(id.unwrap_stanza(&stanza).is_none());
    }

    #[test]
    fn a_tampered_body_returns_none() {
        let id = Identity::generate().expect("generate");
        let (mut stanzas, _) = id
            .to_public()
            .expect("public")
            .wrap_file_key(&file_key(9))
            .expect("wrap");
        stanzas[0].body[0] ^= 0x01;
        assert!(id.unwrap_stanza(&stanzas[0]).is_none());
    }

    #[test]
    fn bech32_round_trips_recipient_and_identity() {
        let id = Identity::generate().expect("generate");
        let recipient = id.to_public().expect("public");

        let r = recipient.to_string();
        let i = id.to_bech32().expect("encode identity");
        assert!(r.starts_with(RECIPIENT_HRP_PREFIX), "got {r}");
        assert!(i.starts_with("AGE-SECRET-KEY-PQ-1"), "got {}", i.as_str());

        assert_eq!(
            Recipient::from_bech32(&r).expect("parse").public_key(),
            recipient.public_key()
        );
        assert_eq!(
            Identity::from_bech32(&i)
                .expect("parse")
                .to_public()
                .expect("public")
                .public_key(),
            recipient.public_key()
        );
    }

    #[test]
    fn a_classical_recipient_is_not_mistaken_for_a_pq_one() {
        let classical = age::x25519::Identity::generate().to_public().to_string();
        assert!(Recipient::from_bech32(&classical).is_err());
        assert!(!classical.starts_with(RECIPIENT_HRP_PREFIX));
    }
}
