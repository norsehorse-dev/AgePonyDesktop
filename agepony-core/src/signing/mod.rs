//! Detached SSHSIG signing and verification.
//!
//! The desktop counterpart of Android's `signing/` package. SSHSIG (OpenSSH
//! `PROTOCOL.sshsig`) is a standardised format, so the signatures produced here
//! interoperate byte for byte with `ssh-keygen -Y sign` and with the mobile
//! apps — proved by the fixtures in `tests/`, which are `ssh-keygen` output.
//!
//! AgePony signs under the namespace [`NAMESPACE`] (`"agepony"`) with a SHA-512
//! message hash, matching `SSHSig.kt`.
//!
//! # Which keys sign
//!
//! In-app SSH keys sign: `ssh-ed25519` and `ssh-rsa` (as `rsa-sha2-512`). age
//! X25519 and post-quantum identities are encryption-only and are rejected with
//! [`CoreError::UnsupportedSigningKey`], as they are on Android. Hardware- and
//! security-key signing is a phone capability (see `PARITY_PLAN.md` F6);
//! signatures made that way still *verify* here.
//!
//! # The RSA workaround
//!
//! `ssh-key` 0.6.7 has a bug in its RSA private-key reconstruction (it uses the
//! prime `p` twice instead of `p` and `q`), so its own RSA signer errors. This
//! module rebuilds the key correctly from the public components and signs with
//! the `rsa` crate directly; the result is byte-identical to `ssh-keygen`.
//! ed25519 signing goes straight through `ssh-key`.

use crate::error::{CoreError, Result};
use rsa::signature::{SignatureEncoding, Signer};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature, SshSig};

pub mod allowed_signers;
pub mod mldsa;
pub mod signers;
pub mod store;

/// The SSHSIG namespace AgePony signs and verifies under.
pub const NAMESPACE: &str = "agepony";

/// The domain-qualified namespace AgePony is moving to, following the
/// `ssh-keygen` recommendation to namespace custom uses as `NAME@DOMAIN`
/// (issue #3). Accepted on verify already; signing still uses [`NAMESPACE`] so
/// signatures keep verifying in un-updated AgePony family apps. Flip the
/// signing default only once Android and iOS also accept both.
//
// TODO(#3): choose the final value before Desktop signs under it. Candidates:
// "agepony@agepony.com" (product domain, matches the open-source.php example)
// or "agepony@pony.norsehor.se" (family domain). Provisional until then.
pub const NAMESPACE_QUALIFIED: &str = "agepony@agepony.com";

/// The namespaces AgePony accepts when verifying, newest first. Signing uses
/// only [`NAMESPACE`]; verification tries these plus any caller-supplied name
/// (see [`verify_detached_any`]).
pub const ACCEPTED_NAMESPACES: &[&str] = &[NAMESPACE_QUALIFIED, NAMESPACE];

/// Sign `message` with an OpenSSH private key, returning an armored SSHSIG.
///
/// `openssh_private_key` is the text of an OpenSSH private key file
/// (`-----BEGIN OPENSSH PRIVATE KEY-----`), decrypted — passphrase-protected
/// keys are unlocked before they reach here.
///
/// # Errors
///
/// [`CoreError::InvalidIdentity`] if the key does not parse,
/// [`CoreError::UnsupportedSigningKey`] for a key type that cannot sign, or
/// [`CoreError::Signing`] if the signature operation itself fails.
pub fn sign_detached(openssh_private_key: &str, message: &[u8], namespace: &str) -> Result<String> {
    if mldsa::is_mldsa_private(openssh_private_key) {
        return mldsa::sign(openssh_private_key, message, namespace);
    }
    let key =
        PrivateKey::from_openssh(openssh_private_key).map_err(|_| CoreError::InvalidIdentity)?;

    let sig = match key.algorithm() {
        Algorithm::Ed25519 => SshSig::sign(&key, namespace, HashAlg::Sha512, message)
            .map_err(|e| CoreError::Signing(e.to_string()))?,
        Algorithm::Rsa { .. } => rsa_sign(&key, message, namespace)?,
        other => return Err(CoreError::UnsupportedSigningKey(other.as_str().to_owned())),
    };

    sig.to_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|e| CoreError::Signing(e.to_string()))
}

/// The result of verifying a detached signature.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// Whether the signature verified cryptographically and the namespace matched.
    pub valid: bool,
    /// The signer key type, e.g. `ssh-ed25519` or `rsa-sha2-512`.
    pub key_type: String,
    /// The signer's SSH public-key wire blob — the exact bytes carried in the
    /// signature, so a trust store matches on it by equality.
    pub signer_wire: Vec<u8>,
    /// The namespace the signature was made under.
    pub namespace: String,
    /// `None` when valid; otherwise why it failed.
    pub reason: Option<String>,
}

/// Verify a detached SSHSIG (armored or raw) over `message`.
///
/// A structurally malformed blob returns [`CoreError::InvalidSignature`]; a
/// well-formed signature that does not verify — wrong key, tampered message, or
/// a namespace mismatch — returns `Ok` with `valid == false` and a `reason`, so
/// callers can distinguish "not a signature" from "not a valid one".
pub fn verify_detached(signature: &[u8], message: &[u8], namespace: &str) -> Result<Verdict> {
    if mldsa::is_mldsa_signature(signature) {
        return mldsa::verify(signature, message, namespace);
    }
    let sig = decode_armored_or_raw(signature)?;
    let public = PublicKey::from(sig.public_key().clone());
    let key_type = sig.algorithm().as_str().to_owned();
    let signer_wire = public
        .to_bytes()
        .map_err(|e| CoreError::Signing(e.to_string()))?;
    let env_namespace = sig.namespace().to_owned();

    if env_namespace != namespace {
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

    match public.verify(namespace, message, &sig) {
        Ok(()) => Ok(Verdict {
            valid: true,
            key_type,
            signer_wire,
            namespace: env_namespace,
            reason: None,
        }),
        Err(e) => Ok(Verdict {
            valid: false,
            key_type,
            signer_wire,
            namespace: env_namespace,
            reason: Some(e.to_string()),
        }),
    }
}

/// Verify a detached SSHSIG accepting any of `namespaces`, tried in order.
///
/// Returns the first namespace under which the signature verifies. If none do,
/// returns the verdict from the last namespace tried, so the caller still sees
/// a real reason (a namespace mismatch, or a bad signature). With an empty
/// `namespaces`, falls back to [`NAMESPACE`].
///
/// A structurally malformed blob returns [`CoreError::InvalidSignature`], the
/// same as [`verify_detached`].
pub fn verify_detached_any(
    signature: &[u8],
    message: &[u8],
    namespaces: &[&str],
) -> Result<Verdict> {
    let mut last = None;
    for &namespace in namespaces {
        let verdict = verify_detached(signature, message, namespace)?;
        if verdict.valid {
            return Ok(verdict);
        }
        last = Some(verdict);
    }
    match last {
        Some(verdict) => Ok(verdict),
        None => verify_detached(signature, message, NAMESPACE),
    }
}

/// The OpenSSH-style SHA256 fingerprint of a public-key wire blob, rendered as
/// `ssh-keygen -lf` prints it (`SHA256:` + unpadded base64). Matches Android's
/// `StoredSigner.sshFingerprint` byte for byte.
///
/// # Errors
///
/// [`CoreError::InvalidSignature`] if `wire` is not a valid SSH public key.
pub fn fingerprint(wire: &[u8]) -> Result<String> {
    let public = PublicKey::from_bytes(wire).map_err(|_| CoreError::InvalidSignature)?;
    Ok(public.fingerprint(HashAlg::Sha256).to_string())
}

// ------------------------------------------------------------------ internal ---

/// Decode an armored (`-----BEGIN SSH SIGNATURE-----`) SSHSIG blob. Armor is the
/// wire form AgePony and `ssh-keygen` write for a detached signature, so a `.sig`
/// file is always PEM.
fn decode_armored_or_raw(input: &[u8]) -> Result<SshSig> {
    SshSig::from_pem(input).map_err(|_| CoreError::InvalidSignature)
}

/// Sign with RSA (`rsa-sha2-512`), rebuilding the key correctly around the
/// `ssh-key` 0.6.7 reconstruction bug. See the module docs.
fn rsa_sign(key: &PrivateKey, message: &[u8], namespace: &str) -> Result<SshSig> {
    let kp = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(kp) => kp,
        _ => return Err(CoreError::Signing("expected an RSA keypair".to_owned())),
    };

    let to_big = |m: &ssh_key::Mpint| -> Result<rsa::BigUint> {
        rsa::BigUint::try_from(m).map_err(|_| CoreError::Signing("bad RSA component".to_owned()))
    };
    let priv_key = rsa::RsaPrivateKey::from_components(
        to_big(&kp.public.n)?,
        to_big(&kp.public.e)?,
        to_big(&kp.private.d)?,
        vec![to_big(&kp.private.p)?, to_big(&kp.private.q)?],
    )
    .map_err(|e| CoreError::Signing(e.to_string()))?;

    let signer = RsaSigner {
        inner: rsa::pkcs1v15::SigningKey::<sha2_rsa::Sha512>::new(priv_key),
        public: key.public_key().key_data().clone(),
    };
    SshSig::sign(&signer, namespace, HashAlg::Sha512, message)
        .map_err(|e| CoreError::Signing(e.to_string()))
}

/// A `SigningKey` that produces `rsa-sha2-512` signatures from a correctly
/// reconstructed RSA key.
struct RsaSigner {
    inner: rsa::pkcs1v15::SigningKey<sha2_rsa::Sha512>,
    public: KeyData,
}

impl Signer<Signature> for RsaSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, rsa::signature::Error> {
        let sig = self
            .inner
            .try_sign(msg)
            .map_err(|_| rsa::signature::Error::new())?;
        Signature::new(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            sig.to_bytes().to_vec(),
        )
        .map_err(|_| rsa::signature::Error::new())
    }
}

impl ssh_key::SigningKey for RsaSigner {
    fn public_key(&self) -> KeyData {
        self.public.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = include_bytes!("../../tests/fixtures/sshsig_message.txt");
    const ED_KEY: &str = include_str!("../../tests/fixtures/sshsig_ed25519_key");
    const RSA_KEY: &str = include_str!("../../tests/fixtures/sshsig_rsa_key");
    const ED_REF: &[u8] = include_bytes!("../../tests/fixtures/sshsig_ed25519.sig");
    const RSA_REF: &[u8] = include_bytes!("../../tests/fixtures/sshsig_rsa.sig");

    #[test]
    fn ed25519_signature_is_byte_identical_to_ssh_keygen() {
        let ours = sign_detached(ED_KEY, MSG, NAMESPACE).expect("sign");
        let reference = std::str::from_utf8(ED_REF).unwrap();
        assert_eq!(ours.trim_end(), reference.trim_end());
    }

    #[test]
    fn rsa_signature_is_byte_identical_to_ssh_keygen() {
        // RSA PKCS#1 v1.5 is deterministic, so this is an exact match, and it
        // exercises the reconstruct-the-key workaround end to end.
        let ours = sign_detached(RSA_KEY, MSG, NAMESPACE).expect("sign");
        let reference = std::str::from_utf8(RSA_REF).unwrap();
        assert_eq!(ours.trim_end(), reference.trim_end());
    }

    #[test]
    fn we_verify_our_own_ed25519_signature() {
        let sig = sign_detached(ED_KEY, MSG, NAMESPACE).expect("sign");
        let v = verify_detached(sig.as_bytes(), MSG, NAMESPACE).expect("verify");
        assert!(v.valid, "{:?}", v.reason);
        assert_eq!(v.key_type, "ssh-ed25519");
        assert!(!v.signer_wire.is_empty());
    }

    #[test]
    fn we_verify_a_reference_rsa_signature() {
        // Cross-device: verify an rsa-sha2-512 signature ssh-keygen made.
        let v = verify_detached(RSA_REF, MSG, NAMESPACE).expect("verify");
        assert!(v.valid, "{:?}", v.reason);
        assert_eq!(v.key_type, "rsa-sha2-512");
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let sig = sign_detached(ED_KEY, MSG, NAMESPACE).expect("sign");
        let v = verify_detached(sig.as_bytes(), b"a different message", NAMESPACE).expect("verify");
        assert!(!v.valid);
        assert!(v.reason.is_some());
    }

    #[test]
    fn a_namespace_mismatch_is_reported_not_a_pass() {
        let sig = sign_detached(ED_KEY, MSG, NAMESPACE).expect("sign");
        let v = verify_detached(sig.as_bytes(), MSG, "other").expect("verify");
        assert!(!v.valid);
        assert!(v.reason.unwrap().contains("namespace"));
    }

    #[test]
    fn an_x25519_identity_cannot_sign() {
        // An age identity file is not an OpenSSH key, so it fails to parse as
        // one — the "encryption-only key cannot sign" guarantee, from the other
        // side. (A real UI never offers an age identity to the signer.)
        let age_identity = include_str!("../../tests/fixtures/x25519_identity.txt");
        assert!(matches!(
            sign_detached(age_identity, MSG, NAMESPACE),
            Err(CoreError::InvalidIdentity | CoreError::UnsupportedSigningKey(_))
        ));
    }

    #[test]
    fn garbage_is_not_a_signature() {
        assert!(matches!(
            verify_detached(b"not a signature at all", MSG, NAMESPACE),
            Err(CoreError::InvalidSignature)
        ));
    }

    #[test]
    fn fingerprint_matches_ssh_keygen_format() {
        let v = verify_detached(ED_REF, MSG, NAMESPACE).expect("verify");
        let fp = fingerprint(&v.signer_wire).expect("fingerprint");
        assert!(fp.starts_with("SHA256:"));
        // ssh-keygen prints unpadded base64, so no '=' padding.
        assert!(!fp.contains('='));
    }

    #[test]
    fn verify_any_accepts_both_the_legacy_and_qualified_namespaces() {
        let legacy = sign_detached(ED_KEY, MSG, NAMESPACE).expect("sign");
        let qualified = sign_detached(ED_KEY, MSG, NAMESPACE_QUALIFIED).expect("sign");
        assert!(
            verify_detached_any(legacy.as_bytes(), MSG, ACCEPTED_NAMESPACES)
                .expect("verify")
                .valid
        );
        assert!(
            verify_detached_any(qualified.as_bytes(), MSG, ACCEPTED_NAMESPACES)
                .expect("verify")
                .valid
        );
    }

    #[test]
    fn verify_any_reports_invalid_for_a_foreign_namespace() {
        let foreign = sign_detached(ED_KEY, MSG, "someone@example.org").expect("sign");
        let v = verify_detached_any(foreign.as_bytes(), MSG, ACCEPTED_NAMESPACES).expect("verify");
        assert!(!v.valid);
        assert!(v.reason.is_some());
    }

    #[test]
    fn verify_any_accepts_a_caller_supplied_namespace() {
        let sig = sign_detached(ED_KEY, MSG, "custom@example.com").expect("sign");
        let namespaces = ["custom@example.com", NAMESPACE];
        assert!(
            verify_detached_any(sig.as_bytes(), MSG, &namespaces)
                .expect("verify")
                .valid
        );
    }
}
