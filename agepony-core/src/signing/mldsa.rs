//! Native `mldsa44-ed25519` composite SSHSIG signing and verification.
//!
//! OpenSSH 10.4 added the composite post-quantum signature `mldsa44-ed25519`
//! (`draft-miller-sshm-mldsa44-ed25519-composite-sigs`): an ML-DSA-44 signature
//! and an Ed25519 signature over one shared representative, both required to
//! verify. `ssh-key` has no such algorithm, so AgePony implements it natively
//! with RustCrypto `ml-dsa` and `ed25519-dalek`. The output is byte-for-byte
//! interoperable with `ssh-keygen` (proven against fixtures; see the tests and
//! `MLDSA_SPIKE_FINDINGS.md`).
//!
//! Keys are stored as their two 32-byte seeds (ML-DSA seed then Ed25519 seed),
//! wrapped in a small AgePony PEM block, since `ssh-key` cannot serialise the
//! OpenSSH private-key form of a composite key. The public line and signatures
//! are the exact OpenSSH wire format.

use crate::error::{CoreError, Result};
use crate::signing::Verdict;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD};
use ml_dsa::{Keypair as _, MlDsa44};
use sha2::{Digest, Sha256, Sha512};

/// The OpenSSH algorithm name for the composite key.
pub const ALG_NAME: &str = "ssh-mldsa44-ed25519@openssh.com";

const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
const MLDSA_PK: usize = 1312;
const MLDSA_SIG: usize = 2420;
const ED_PK: usize = 32;
const ED_SIG: usize = 64;
const SEED_MARKER: &str = "AGEPONY MLDSA44-ED25519 SEED";

// ---- SSH wire helpers (no indexing, no panics) ------------------------------

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
}

struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.o.checked_add(n).ok_or(CoreError::InvalidSignature)?;
        let s = self.b.get(self.o..end).ok_or(CoreError::InvalidSignature)?;
        self.o = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<usize> {
        let a: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CoreError::InvalidSignature)?;
        Ok(u32::from_be_bytes(a) as usize)
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()?;
        self.take(n)
    }
}

// ---- key material -----------------------------------------------------------

struct KeyMaterial {
    public_line: String,
    fingerprint: String,
    pubkey_blob: Vec<u8>,
}

fn from_seeds(mldsa_seed: &[u8; 32], ed_seed: &[u8; 32]) -> Result<KeyMaterial> {
    let seed = ml_dsa::B32::try_from(mldsa_seed.as_slice())
        .map_err(|_| CoreError::Signing("bad ML-DSA seed".to_owned()))?;
    let msk = ml_dsa::SigningKey::<MlDsa44>::from_seed(&seed);
    let mldsa_pk = msk.verifying_key().encode();
    let esk = ed25519_dalek::SigningKey::from_bytes(ed_seed);
    let ed_pk = esk.verifying_key().to_bytes();

    let mut comp_pk = Vec::with_capacity(MLDSA_PK + ED_PK);
    comp_pk.extend_from_slice(mldsa_pk.as_slice());
    comp_pk.extend_from_slice(&ed_pk);

    let mut blob = Vec::new();
    put_str(&mut blob, ALG_NAME.as_bytes());
    put_str(&mut blob, &comp_pk);

    let public_line = format!("{ALG_NAME} {}", BASE64.encode(&blob));
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)));
    Ok(KeyMaterial {
        public_line,
        fingerprint,
        pubkey_blob: blob,
    })
}

/// A freshly generated composite signing key, ready for the store.
pub struct Generated {
    /// OpenSSH public line (`ssh-mldsa44-ed25519@openssh.com AAAA...`).
    pub public_line: String,
    /// `SHA256:...` fingerprint, as `ssh-keygen -lf` prints it.
    pub fingerprint: String,
    /// The private material as an AgePony PEM seed block, to store as the secret.
    pub secret: String,
}

/// Generate a new `mldsa44-ed25519` signing key.
///
/// # Errors
/// [`CoreError::Signing`] if the underlying key generation fails.
pub fn generate() -> Result<Generated> {
    use rand_core::RngCore as _;
    let mut rng = rand_core::OsRng;
    let mut mldsa_seed = [0u8; 32];
    let mut ed_seed = [0u8; 32];
    rng.fill_bytes(&mut mldsa_seed);
    rng.fill_bytes(&mut ed_seed);
    let km = from_seeds(&mldsa_seed, &ed_seed)?;

    let mut sk = Vec::with_capacity(64);
    sk.extend_from_slice(&mldsa_seed);
    sk.extend_from_slice(&ed_seed);
    let secret = pem_wrap(&BASE64.encode(&sk));
    Ok(Generated {
        public_line: km.public_line,
        fingerprint: km.fingerprint,
        secret,
    })
}

fn pem_wrap(b64: &str) -> String {
    let mut out = format!("-----BEGIN {SEED_MARKER}-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {SEED_MARKER}-----\n"));
    out
}

/// Whether a stored secret is an AgePony composite seed block (vs an OpenSSH key).
#[must_use]
pub fn is_mldsa_private(secret: &str) -> bool {
    secret.contains(SEED_MARKER)
}

fn parse_secret(secret: &str) -> Result<([u8; 32], [u8; 32])> {
    let body: String = secret
        .lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .collect();
    let raw = BASE64
        .decode(body.trim())
        .map_err(|_| CoreError::InvalidIdentity)?;
    if raw.len() != 64 {
        return Err(CoreError::InvalidIdentity);
    }
    let mut m = [0u8; 32];
    let mut e = [0u8; 32];
    m.copy_from_slice(raw.get(0..32).ok_or(CoreError::InvalidIdentity)?);
    e.copy_from_slice(raw.get(32..64).ok_or(CoreError::InvalidIdentity)?);
    Ok((m, e))
}

// ---- the composite representative -------------------------------------------

fn representative(namespace: &str, message: &[u8]) -> Vec<u8> {
    // The SSHSIG signed blob (PROTOCOL.sshsig), hash_algorithm = sha512.
    let mut signed = Vec::new();
    signed.extend_from_slice(b"SSHSIG");
    put_str(&mut signed, namespace.as_bytes());
    put_str(&mut signed, b"");
    put_str(&mut signed, b"sha512");
    put_str(&mut signed, &Sha512::digest(message));
    // m' = PREFIX || LABEL || u8(ctxlen=0) || SHA512(signed)
    let mut m = Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + 64);
    m.extend_from_slice(PREFIX);
    m.extend_from_slice(LABEL);
    m.push(0u8);
    m.extend_from_slice(&Sha512::digest(&signed));
    m
}

// ---- sign -------------------------------------------------------------------

/// Sign `message` under `namespace`, returning an armored SSHSIG.
///
/// # Errors
/// [`CoreError::InvalidIdentity`] if the secret does not parse, or
/// [`CoreError::Signing`] if the signature operation fails.
pub fn sign(secret: &str, message: &[u8], namespace: &str) -> Result<String> {
    use ed25519_dalek::Signer as _;
    let (mldsa_seed, ed_seed) = parse_secret(secret)?;
    let km = from_seeds(&mldsa_seed, &ed_seed)?;
    let seed = ml_dsa::B32::try_from(mldsa_seed.as_slice())
        .map_err(|_| CoreError::Signing("bad ML-DSA seed".to_owned()))?;
    let msk = ml_dsa::SigningKey::<MlDsa44>::from_seed(&seed);
    let esk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);

    let m = representative(namespace, message);
    let mldsa_sig = msk
        .expanded_key()
        .sign_deterministic(&m, LABEL)
        .map_err(|_| CoreError::Signing("ML-DSA signing failed".to_owned()))?
        .encode();
    let ed_sig = esk.sign(&m).to_bytes();

    let mut comp_sig = Vec::with_capacity(MLDSA_SIG + ED_SIG);
    comp_sig.extend_from_slice(mldsa_sig.as_slice());
    comp_sig.extend_from_slice(&ed_sig);

    let mut sigblob = Vec::new();
    put_str(&mut sigblob, ALG_NAME.as_bytes());
    put_str(&mut sigblob, &comp_sig);

    let mut env = Vec::new();
    env.extend_from_slice(b"SSHSIG");
    env.extend_from_slice(&1u32.to_be_bytes());
    put_str(&mut env, &km.pubkey_blob);
    put_str(&mut env, namespace.as_bytes());
    put_str(&mut env, b"");
    put_str(&mut env, b"sha512");
    put_str(&mut env, &sigblob);

    Ok(armor(&env))
}

fn armor(blob: &[u8]) -> String {
    let b64 = BASE64.encode(blob);
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    out
}

fn dearmor(input: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(input).map_err(|_| CoreError::InvalidSignature)?;
    let body: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .collect();
    BASE64
        .decode(body.trim())
        .map_err(|_| CoreError::InvalidSignature)
}

/// Whether an armored SSHSIG is a composite `mldsa44-ed25519` signature.
#[must_use]
pub fn is_mldsa_signature(signature: &[u8]) -> bool {
    envelope_name(signature)
        .map(|n| n == ALG_NAME.as_bytes())
        .unwrap_or(false)
}

fn envelope_name(signature: &[u8]) -> Result<Vec<u8>> {
    let raw = dearmor(signature)?;
    let mut r = Reader::new(&raw);
    if r.take(6)? != b"SSHSIG" {
        return Err(CoreError::InvalidSignature);
    }
    let _ver = r.u32()?;
    let publickey = r.string()?;
    Ok(Reader::new(publickey).string()?.to_vec())
}

// ---- verify -----------------------------------------------------------------

/// Verify an armored composite SSHSIG over `message` under `namespace`.
///
/// # Errors
/// [`CoreError::InvalidSignature`] if the blob is structurally malformed.
pub fn verify(signature: &[u8], message: &[u8], namespace: &str) -> Result<Verdict> {
    use ed25519_dalek::Verifier as _;
    let raw = dearmor(signature)?;
    let mut r = Reader::new(&raw);
    if r.take(6)? != b"SSHSIG" {
        return Err(CoreError::InvalidSignature);
    }
    let _ver = r.u32()?;
    let publickey = r.string()?;
    let env_ns = r.string()?;
    let _reserved = r.string()?;
    let hash_alg = r.string()?;
    let sigblob = r.string()?;

    let mut pr = Reader::new(publickey);
    let pk_name = pr.string()?;
    let comp_pk = pr.string()?;
    if pk_name != ALG_NAME.as_bytes() {
        return Err(CoreError::InvalidSignature);
    }
    let mldsa_pk = comp_pk.get(0..MLDSA_PK).ok_or(CoreError::InvalidSignature)?;
    let ed_pk = comp_pk
        .get(MLDSA_PK..MLDSA_PK + ED_PK)
        .ok_or(CoreError::InvalidSignature)?;

    let mut sr = Reader::new(sigblob);
    let _sig_name = sr.string()?;
    let comp_sig = sr.string()?;
    let mldsa_sig = comp_sig.get(0..MLDSA_SIG).ok_or(CoreError::InvalidSignature)?;
    let ed_sig = comp_sig
        .get(MLDSA_SIG..MLDSA_SIG + ED_SIG)
        .ok_or(CoreError::InvalidSignature)?;

    let key_type = ALG_NAME.to_owned();
    let signer_wire = publickey.to_vec();
    let env_namespace = String::from_utf8_lossy(env_ns).into_owned();

    if env_ns != namespace.as_bytes() {
        return Ok(Verdict {
            valid: false,
            key_type,
            signer_wire,
            namespace: env_namespace.clone(),
            reason: Some(format!(
                "namespace mismatch: got '{env_namespace}', expected '{namespace}'"
            )),
        });
    }
    if hash_alg != b"sha512" {
        return Ok(Verdict {
            valid: false,
            key_type,
            signer_wire,
            namespace: env_namespace,
            reason: Some("unsupported hash algorithm".to_owned()),
        });
    }

    let m = representative(namespace, message);

    let vk_enc = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(mldsa_pk)
        .map_err(|_| CoreError::InvalidSignature)?;
    let vk = ml_dsa::VerifyingKey::<MlDsa44>::decode(&vk_enc);
    let sig =
        ml_dsa::Signature::<MlDsa44>::try_from(mldsa_sig).map_err(|_| CoreError::InvalidSignature)?;
    let mldsa_ok = vk.verify_with_context(&m, LABEL, &sig);

    let ed_pk_arr: [u8; 32] = ed_pk.try_into().map_err(|_| CoreError::InvalidSignature)?;
    let ed_sig_arr: [u8; 64] = ed_sig.try_into().map_err(|_| CoreError::InvalidSignature)?;
    let ed_ok = ed25519_dalek::VerifyingKey::from_bytes(&ed_pk_arr)
        .map(|k| k.verify(&m, &ed25519_dalek::Signature::from_bytes(&ed_sig_arr)).is_ok())
        .unwrap_or(false);

    if mldsa_ok && ed_ok {
        Ok(Verdict {
            valid: true,
            key_type,
            signer_wire,
            namespace: env_namespace,
            reason: None,
        })
    } else {
        Ok(Verdict {
            valid: false,
            key_type,
            signer_wire,
            namespace: env_namespace,
            reason: Some("signature did not verify".to_owned()),
        })
    }
}
