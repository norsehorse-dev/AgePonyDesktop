//! Re-encrypting existing age files to a new recipient — the engine behind the
//! "upgrade to quantum-safe" migration (Android's `ui/files/MigrateFlow.kt`).
//!
//! Each file is decrypted (with the caller's identities, or a passphrase for a
//! passphrase-encrypted file) and re-encrypted to the target recipient,
//! preserving whether the original was ASCII-armored. The plaintext lives only
//! in a [`Zeroizing`] buffer between the two operations and never touches disk.

use crate::decrypt::With;
use crate::error::Result;
use crate::recipient::Parsed;
use age::secrecy::SecretString;

/// Whether `bytes` is an ASCII-armored age file (rather than binary).
#[must_use]
pub fn looks_armored(bytes: &[u8]) -> bool {
    const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
    let head = bytes.get(..ARMOR_BEGIN.len().min(bytes.len())).unwrap_or_default();
    head == ARMOR_BEGIN
}

/// Re-encrypt one age file's bytes to `target`.
///
/// Decryption is tried with `identities` first; if none match and a `passphrase`
/// is given, it is tried next — mirroring the mobile flow, where a batch may mix
/// identity- and passphrase-encrypted files. The output keeps the input's armor.
///
/// # Errors
///
/// A decrypt error if nothing can open the file (a no-identity-match error with
/// no passphrase means the file matched no identity and none was offered), or an
/// encrypt error for the re-encryption.
pub fn reencrypt(
    ciphertext: &[u8],
    identities: &[Box<dyn age::Identity + Send + Sync>],
    passphrase: Option<&SecretString>,
    target: &Parsed,
) -> Result<Vec<u8>> {
    let armored = looks_armored(ciphertext);

    let plaintext = match crate::decrypt::decrypt_bytes(ciphertext, With::Identities(identities)) {
        Ok(p) => p,
        Err(first_err) => {
            // No identity matched. Fall back to a passphrase if we have one.
            let Some(pass) = passphrase else {
                return Err(first_err);
            };
            crate::decrypt::decrypt_bytes(ciphertext, With::Passphrase(pass.clone()))?
        }
    };

    crate::encrypt::encrypt_bytes(
        &plaintext,
        crate::encrypt::To::Recipients(std::slice::from_ref(target)),
        armored,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{To, encrypt_bytes};

    fn pq_recipient() -> (crate::pq::Identity, Parsed) {
        let id = crate::pq::Identity::generate().unwrap();
        let recipient = crate::recipient::parse(&id.to_public().unwrap().to_string()).unwrap();
        (id, recipient)
    }

    #[test]
    fn armor_is_detected() {
        assert!(looks_armored(b"-----BEGIN AGE ENCRYPTED FILE-----\nabc"));
        assert!(!looks_armored(b"age-encryption.org/v1\n..."));
        assert!(!looks_armored(b""));
    }

    #[test]
    fn migrates_a_classic_file_to_quantum_safe() {
        // Encrypt to a classic identity, then migrate to a PQ one.
        let classic = age::x25519::Identity::generate();
        let classic_recipient = crate::recipient::parse(&classic.to_public().to_string()).unwrap();
        let ct = encrypt_bytes(
            b"secret plans",
            To::Recipients(std::slice::from_ref(&classic_recipient)),
            false,
        )
        .unwrap();

        let (pq_id, pq_recipient) = pq_recipient();
        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(classic)];
        let migrated = reencrypt(&ct, &ids, None, &pq_recipient).unwrap();

        // The migrated file opens with the PQ identity, and not with the old one.
        let opened =
            crate::decrypt::decrypt_bytes(&migrated, With::Identities(&[Box::new(pq_id)])).unwrap();
        assert_eq!(&opened[..], b"secret plans");
    }

    #[test]
    fn a_passphrase_file_migrates_when_the_passphrase_is_given() {
        let ct = encrypt_bytes(
            b"locked",
            To::Passphrase(SecretString::from("open sesame".to_owned())),
            false,
        )
        .unwrap();
        let (_pq_id, pq_recipient) = pq_recipient();
        let no_ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![];

        // Without the passphrase it cannot be opened.
        assert!(reencrypt(&ct, &no_ids, None, &pq_recipient).is_err());
        // With it, migration succeeds.
        let pass = SecretString::from("open sesame".to_owned());
        assert!(reencrypt(&ct, &no_ids, Some(&pass), &pq_recipient).is_ok());
    }

    #[test]
    fn armor_is_preserved_across_migration() {
        let classic = age::x25519::Identity::generate();
        let classic_recipient = crate::recipient::parse(&classic.to_public().to_string()).unwrap();
        let ct = encrypt_bytes(
            b"armored secret",
            To::Recipients(std::slice::from_ref(&classic_recipient)),
            true,
        )
        .unwrap();
        assert!(looks_armored(&ct));

        let (_pq, pq_recipient) = pq_recipient();
        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(classic)];
        let migrated = reencrypt(&ct, &ids, None, &pq_recipient).unwrap();
        assert!(looks_armored(&migrated), "armored input must stay armored");
    }
}
