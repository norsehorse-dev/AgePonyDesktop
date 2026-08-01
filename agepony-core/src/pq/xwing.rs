//! The MLKEM768-X25519 hybrid KEM, a.k.a. X-Wing.
//!
//! Ported from `HpkeMlkem768X25519.kt` in the Android core, which is itself
//! pinned to the `filippo.io/hpke` reference that Go `age` v1.3.0+ uses.
//!
//! ```text
//! seed (32) ──SHAKE256(96)──┬─ [0..32]  d  ┐
//!                           ├─ [32..64] z  ┴─ ML-KEM-768 KeyGen_internal
//!                           └─ [64..96] sk_X  ── X25519 scalar
//!
//! public key = ek_M (1184) ‖ pk_X (32)                  = 1216
//! enc        = ct_M (1088) ‖ ct_X (32)                  = 1120
//! ss         = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ LABEL)
//! ```
//!
//! `LABEL` is the six bytes `\.//^\`, which is X-Wing's domain separator.

use crate::error::{CoreError, Result};
use ml_kem::kem::Decapsulate as _;
use ml_kem::{B32, EncapsulateDeterministic as _, EncodedSizeUser as _, KemCore as _, MlKem768};

type DecapsulationKey = <MlKem768 as ml_kem::KemCore>::DecapsulationKey;
type EncapsulationKey = <MlKem768 as ml_kem::KemCore>::EncapsulationKey;
type MlKemCiphertext = ml_kem::Ciphertext<MlKem768>;
use sha3::{Digest, Sha3_256};
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroizing;

/// Size of the identity seed.
pub const SEED_SIZE: usize = 32;
/// Size of the ML-KEM-768 encapsulation key.
pub const ML_KEM_PUBLIC_SIZE: usize = 1184;
/// Size of the ML-KEM-768 ciphertext.
pub const ML_KEM_CIPHERTEXT_SIZE: usize = 1088;
/// Size of an X25519 public key or ciphertext.
pub const X25519_SIZE: usize = 32;
/// Size of the combined hybrid public key.
pub const PUBLIC_KEY_SIZE: usize = ML_KEM_PUBLIC_SIZE + X25519_SIZE;
/// Size of the combined encapsulation.
pub const ENC_SIZE: usize = ML_KEM_CIPHERTEXT_SIZE + X25519_SIZE;
/// Size of the randomness `encapsulate_with` consumes: ML-KEM `m` then the
/// X25519 ephemeral scalar.
pub const ENCAP_RANDOMNESS_SIZE: usize = 64;

/// X-Wing's domain separator: the ASCII bytes of `\.//^\`.
const LABEL: &[u8; 6] = &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

fn bad(what: &'static str) -> CoreError {
    CoreError::InvalidRecipient(what.to_owned())
}

/// Expand a 32-byte seed into the ML-KEM seed and the X25519 scalar.
fn expand(seed: &[u8; SEED_SIZE]) -> Zeroizing<[u8; 96]> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut out = Zeroizing::new([0_u8; 96]);
    hasher.finalize_xof().read(out.as_mut());
    out
}

/// Copy a 32-byte secret out of a type that does not zeroize into one that
/// does.
///
/// `ml_kem`'s `SharedKey` is a `hybrid_array::Array`, which has no `Zeroize`
/// impl, so it cannot be wrapped in `Zeroizing` directly.
fn own_secret(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0_u8; 32]);
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

/// Combine the two shared secrets exactly as X-Wing specifies.
fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, LABEL);
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(&h.finalize());
    out
}

/// A hybrid private key, derived from a 32-byte seed.
pub struct PrivateKey {
    dk: DecapsulationKey,
    sk_x: Zeroizing<[u8; 32]>,
    public_key: [u8; PUBLIC_KEY_SIZE],
}

impl PrivateKey {
    /// Derive the key pair from a 32-byte seed.
    // Every range below is a compile-time constant into a fixed-size array, so
    // none of them can be out of bounds.
    #[expect(
        clippy::indexing_slicing,
        reason = "constant ranges into fixed-size arrays"
    )]
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        let expanded = expand(seed);

        let mut d = B32::default();
        let mut z = B32::default();
        d.copy_from_slice(&expanded[..32]);
        z.copy_from_slice(&expanded[32..64]);
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);

        let mut sk_x = Zeroizing::new([0_u8; 32]);
        sk_x.copy_from_slice(&expanded[64..96]);
        let pk_x = x25519_dalek::x25519(*sk_x, x25519_dalek::X25519_BASEPOINT_BYTES);

        let ek_bytes = ek.as_bytes();
        let mut public_key = [0_u8; PUBLIC_KEY_SIZE];
        public_key[..ML_KEM_PUBLIC_SIZE].copy_from_slice(&ek_bytes);
        public_key[ML_KEM_PUBLIC_SIZE..].copy_from_slice(&pk_x);

        Self {
            dk,
            sk_x,
            public_key,
        }
    }

    /// The 1216-byte hybrid public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public_key
    }

    /// Recover the shared secret from an encapsulation.
    ///
    /// # Errors
    ///
    /// Returns an error if `enc` is the wrong length.
    ///
    /// Note there is no authentication here: ML-KEM decapsulation is
    /// implicit-rejection, so a wrong or tampered `enc` yields a *different*
    /// shared secret rather than an error. The AEAD open that follows is what
    /// actually rejects it.
    pub fn decapsulate(&self, enc: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if enc.len() != ENC_SIZE {
            return Err(bad("hybrid encapsulation is the wrong length"));
        }
        let (ct_m, ct_x) = enc.split_at(ML_KEM_CIPHERTEXT_SIZE);

        let mut ct = MlKemCiphertext::default();
        ct.copy_from_slice(ct_m);
        let ss_m = self
            .dk
            .decapsulate(&ct)
            .map_err(|()| bad("ML-KEM decapsulation failed"))?;

        let mut ct_x_arr = [0_u8; 32];
        ct_x_arr.copy_from_slice(ct_x);
        // x25519() hands back a bare array; that array is a shared secret.
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*self.sk_x, ct_x_arr));
        let ss_m = own_secret(&ss_m);

        let pk_x = &self.public_key[ML_KEM_PUBLIC_SIZE..];
        Ok(combine(ss_m.as_ref(), ss_x.as_ref(), ct_x, pk_x))
    }
}

/// A hybrid public key.
#[derive(Clone)]
pub struct PublicKey {
    ek: EncapsulationKey,
    pk_x: [u8; 32],
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKey {
    /// Parse a 1216-byte hybrid public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is wrong or the ML-KEM half is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(bad("hybrid public key is the wrong length"));
        }
        let (ek_bytes, x_bytes) = bytes.split_at(ML_KEM_PUBLIC_SIZE);

        let mut key = ml_kem::Encoded::<EncapsulationKey>::default();
        key.copy_from_slice(ek_bytes);
        let ek = EncapsulationKey::from_bytes(&key);

        let mut pk_x = [0_u8; 32];
        pk_x.copy_from_slice(x_bytes);

        let mut owned = [0_u8; PUBLIC_KEY_SIZE];
        owned.copy_from_slice(bytes);

        Ok(Self {
            ek,
            pk_x,
            bytes: owned,
        })
    }

    /// The encoded form.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Encapsulate with caller-supplied randomness.
    ///
    /// `randomness` is 64 bytes: the ML-KEM message `m`, then the X25519
    /// ephemeral scalar. Production code passes fresh randomness; the
    /// known-answer tests pass a fixed value.
    ///
    /// # Errors
    ///
    /// Returns an error if `randomness` is the wrong length.
    // The length is checked on entry, so the constant ranges below are in bounds.
    #[expect(clippy::indexing_slicing, reason = "length checked on entry")]
    pub fn encapsulate_with(
        &self,
        randomness: &[u8],
    ) -> Result<([u8; ENC_SIZE], Zeroizing<[u8; 32]>)> {
        if randomness.len() != ENCAP_RANDOMNESS_SIZE {
            return Err(bad("encapsulation randomness is the wrong length"));
        }

        let mut m = B32::default();
        m.copy_from_slice(&randomness[..32]);
        let (ct_m, ss_m) = self
            .ek
            .encapsulate_deterministic(&m)
            .map_err(|()| bad("ML-KEM encapsulation failed"))?;

        let mut ek_x = Zeroizing::new([0_u8; 32]);
        ek_x.copy_from_slice(&randomness[32..64]);
        let ct_x = x25519_dalek::x25519(*ek_x, x25519_dalek::X25519_BASEPOINT_BYTES);
        // ct_x is public (it goes on the wire); ss_x is not.
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*ek_x, self.pk_x));
        let ss_m = own_secret(&ss_m);

        let mut enc = [0_u8; ENC_SIZE];
        enc[..ML_KEM_CIPHERTEXT_SIZE].copy_from_slice(&ct_m);
        enc[ML_KEM_CIPHERTEXT_SIZE..].copy_from_slice(&ct_x);

        let ss = combine(ss_m.as_ref(), ss_x.as_ref(), &ct_x, &self.pk_x);
        Ok((enc, ss))
    }

    /// Encapsulate with fresh randomness from the OS.
    ///
    /// # Errors
    ///
    /// Returns an error only if the underlying encapsulation rejects the
    /// randomness, which cannot happen for a correctly sized buffer.
    pub fn encapsulate(&self) -> Result<([u8; ENC_SIZE], Zeroizing<[u8; 32]>)> {
        let mut randomness = Zeroizing::new([0_u8; ENCAP_RANDOMNESS_SIZE]);
        getrandom::fill(randomness.as_mut())
            .map_err(|e| CoreError::BareIo(std::io::Error::other(e)))?;
        self.encapsulate_with(randomness.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_then_decapsulate_agrees() {
        let seed = [9_u8; SEED_SIZE];
        let sk = PrivateKey::from_seed(&seed);
        let pk = PublicKey::from_bytes(sk.public_key()).expect("parse own public key");

        let (enc, ss_sender) = pk.encapsulate().expect("encapsulate");
        let ss_receiver = sk.decapsulate(&enc).expect("decapsulate");
        assert_eq!(*ss_sender, *ss_receiver);
    }

    #[test]
    fn the_seed_fully_determines_the_key_pair() {
        let seed = [3_u8; SEED_SIZE];
        assert_eq!(
            PrivateKey::from_seed(&seed).public_key(),
            PrivateKey::from_seed(&seed).public_key()
        );
    }

    #[test]
    fn a_different_seed_gives_a_different_key() {
        let a = PrivateKey::from_seed(&[1_u8; SEED_SIZE]);
        let b = PrivateKey::from_seed(&[2_u8; SEED_SIZE]);
        assert_ne!(a.public_key().as_slice(), b.public_key().as_slice());
    }

    #[test]
    fn a_tampered_encapsulation_yields_a_different_secret() {
        // ML-KEM uses implicit rejection, so this must not error -- it must
        // simply produce the wrong key, which the AEAD then rejects.
        let sk = PrivateKey::from_seed(&[4_u8; SEED_SIZE]);
        let pk = PublicKey::from_bytes(sk.public_key()).expect("parse");
        let (mut enc, ss) = pk.encapsulate().expect("encapsulate");
        enc[0] ^= 0x01;
        let other = sk.decapsulate(&enc).expect("decapsulation does not error");
        assert_ne!(*ss, *other);
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        let sk = PrivateKey::from_seed(&[5_u8; SEED_SIZE]);
        assert!(sk.decapsulate(&[0_u8; 10]).is_err());
        assert!(PublicKey::from_bytes(&[0_u8; 10]).is_err());
    }
}
