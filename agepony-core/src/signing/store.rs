//! The signing-key store: OpenSSH private keys AgePony can sign files with.
//!
//! Deliberately separate from the age identity [`crate::store::Store`], which is
//! bound to age recipients and the recipient-book reconcile invariant. A signing
//! key is not an age identity — it cannot decrypt, and it has no age recipient —
//! so it gets its own index and its own key files, and disturbs none of those
//! invariants. (Android keeps both in one encrypted vault; Desktop keeps them in
//! separate files, so separate stores fit better.)
//!
//! ```text
//! <config>/AgePony/
//! ├── signing_keys.json        index: labels, public lines, fingerprints, dates
//! └── signing-keys/
//!     ├── <id>.key             plain OpenSSH private key (cipher=none), 0600
//!     └── <id>.age             passphrase-protected (age-wrapped) key file
//! ```
//!
//! **The index holds no private key material** — only the OpenSSH *public* line
//! and its fingerprint. A key imported passphrase-protected is decrypted once at
//! import (verifying the passphrase and reading the public half) and re-stored
//! as `cipher=none` OpenSSH, optionally re-wrapped with an AgePony passphrase —
//! the same regime the age store uses, and what Android's `IdentityImport` does.

use crate::clock;
use crate::error::{CoreError, Result, io_at};
use age::secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use std::path::{Path, PathBuf};

/// The algorithm of a stored signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningKind {
    /// `ssh-ed25519`.
    Ed25519,
    /// `ssh-rsa` (signs as `rsa-sha2-512`).
    Rsa,
}

impl SigningKind {
    /// The SSH key-type name.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SigningKind::Ed25519 => "ssh-ed25519",
            SigningKind::Rsa => "ssh-rsa",
        }
    }

    fn from_algorithm(alg: &Algorithm) -> Option<Self> {
        match alg {
            Algorithm::Ed25519 => Some(SigningKind::Ed25519),
            Algorithm::Rsa { .. } => Some(SigningKind::Rsa),
            _ => None,
        }
    }
}

/// One signing key in the store. Public metadata only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningEntry {
    /// Stable id, also the file stem.
    pub id: String,
    /// Human label.
    pub label: String,
    /// The OpenSSH public-key line (`ssh-ed25519 AAAA… comment`). Safe to show.
    pub public_line: String,
    /// The `SHA256:…` fingerprint, as `ssh-keygen -lf` prints it.
    pub fingerprint: String,
    /// ed25519 or rsa.
    pub kind: SigningKind,
    /// RFC 3339 creation date, UTC.
    pub created: String,
    /// Whether the stored key file is passphrase protected.
    pub encrypted: bool,
}

impl SigningEntry {
    /// The file name for this entry's private key material.
    #[must_use]
    pub fn file_name(&self) -> String {
        if self.encrypted {
            format!("{}.age", self.id)
        } else {
            format!("{}.key", self.id)
        }
    }

    /// The SSH public-key wire blob, from the `base64` field of [`Self::public_line`].
    /// Used to match a signature made with this key back to this identity.
    #[must_use]
    pub fn public_wire(&self) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let field = self.public_line.split_whitespace().nth(1)?;
        base64::engine::general_purpose::STANDARD
            .decode(field.as_bytes())
            .ok()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Index {
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    entries: Vec<SigningEntry>,
}

const fn one() -> u32 {
    1
}

/// The signing-key store, rooted at a directory.
#[derive(Debug, Clone)]
pub struct SigningStore {
    root: PathBuf,
    index: Index,
}

impl SigningStore {
    /// Open the store at `root`, creating an empty one if nothing is there.
    ///
    /// # Errors
    ///
    /// [`CoreError::Io`] if the index exists but cannot be read,
    /// [`CoreError::CorruptBook`] if it is not valid JSON.
    pub fn open(root: &Path) -> Result<Self> {
        let index_path = root.join("signing_keys.json");
        let index = if index_path.exists() {
            let text = std::fs::read_to_string(&index_path).map_err(io_at(&index_path))?;
            serde_json::from_str(&text)?
        } else {
            Index::default()
        };
        Ok(Self {
            root: root.to_path_buf(),
            index,
        })
    }

    /// Every signing key, newest first.
    #[must_use]
    pub fn entries(&self) -> &[SigningEntry] {
        &self.index.entries
    }

    /// Look a key up by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&SigningEntry> {
        self.index.entries.iter().find(|e| e.id == id)
    }

    /// The path to an entry's private key material.
    #[must_use]
    pub fn path_for(&self, entry: &SigningEntry) -> PathBuf {
        self.root.join("signing-keys").join(entry.file_name())
    }

    /// Import an OpenSSH private key.
    ///
    /// `openssh_text` is the text of an OpenSSH private key file. If it is itself
    /// passphrase-protected, `source_passphrase` unlocks it; the key is then
    /// stored decrypted (`cipher=none`), optionally re-wrapped with
    /// `protect_passphrase` (AgePony's own passphrase encryption).
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidIdentity`] if the text is not an OpenSSH key,
    /// [`CoreError::PassphraseRequired`]/[`CoreError::Decrypt`] for a locked key
    /// with a missing or wrong passphrase, [`CoreError::UnsupportedSigningKey`]
    /// for a key type that cannot sign, or [`CoreError::DuplicateLabel`].
    pub fn import(
        &mut self,
        label: &str,
        openssh_text: &str,
        source_passphrase: Option<&SecretString>,
        protect_passphrase: Option<&SecretString>,
    ) -> Result<SigningEntry> {
        let parsed = PrivateKey::from_openssh(openssh_text).map_err(|_| CoreError::InvalidIdentity)?;

        let key = if parsed.is_encrypted() {
            let pass = source_passphrase.ok_or(CoreError::PassphraseRequired)?;
            parsed
                .decrypt(pass.expose_secret().as_bytes())
                .map_err(|_| CoreError::InvalidIdentity)?
        } else {
            parsed
        };

        let kind = SigningKind::from_algorithm(&key.algorithm())
            .ok_or_else(|| CoreError::UnsupportedSigningKey(key.algorithm().as_str().to_owned()))?;
        let public_line = key
            .public_key()
            .to_openssh()
            .map_err(|e| CoreError::Signing(e.to_string()))?;
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let secret = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| CoreError::Signing(e.to_string()))?;

        self.insert(label, &public_line, &fingerprint, kind, &secret, protect_passphrase)
    }

    fn insert(
        &mut self,
        label: &str,
        public_line: &str,
        fingerprint: &str,
        kind: SigningKind,
        secret_openssh: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<SigningEntry> {
        let label = label.trim();
        if label.is_empty() {
            return Err(CoreError::DuplicateLabel(String::new()));
        }
        if self.index.entries.iter().any(|e| e.label == label) {
            return Err(CoreError::DuplicateLabel(label.to_owned()));
        }

        let entry = SigningEntry {
            id: self.next_id(),
            label: label.to_owned(),
            public_line: public_line.trim().to_owned(),
            fingerprint: fingerprint.to_owned(),
            kind,
            created: clock::now_rfc3339(),
            encrypted: passphrase.is_some(),
        };

        let path = self.path_for(&entry);
        match passphrase {
            Some(p) => crate::identity::save_encrypted_identity_file(&path, secret_openssh, p)?,
            None => crate::identity::save_identity_file(&path, secret_openssh)?,
        }

        self.index.entries.insert(0, entry.clone());
        self.save()?;
        Ok(entry)
    }

    /// Rename a signing key.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSuchIdentity`] or [`CoreError::DuplicateLabel`].
    pub fn rename(&mut self, id: &str, label: &str) -> Result<()> {
        let label = label.trim().to_owned();
        if self
            .index
            .entries
            .iter()
            .any(|e| e.label == label && e.id != id)
        {
            return Err(CoreError::DuplicateLabel(label));
        }
        let entry = self
            .index
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(CoreError::NoSuchIdentity)?;
        entry.label = label;
        self.save()
    }

    /// Delete a signing key and its private key material.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSuchIdentity`], or [`CoreError::Io`] if the key file cannot
    /// be removed — in which case the index is left untouched.
    pub fn delete(&mut self, id: &str) -> Result<()> {
        let (position, entry) = self
            .index
            .entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.id == id)
            .map(|(i, e)| (i, e.clone()))
            .ok_or(CoreError::NoSuchIdentity)?;

        let path = self.path_for(&entry);
        if path.exists() {
            std::fs::remove_file(&path).map_err(io_at(&path))?;
        }
        self.index.entries.remove(position);
        self.save()
    }

    /// Sign `message` with the stored key `id`, returning an armored SSHSIG.
    ///
    /// `passphrase` unlocks the key file if it is protected.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSuchIdentity`], [`CoreError::PassphraseRequired`] /
    /// [`CoreError::Decrypt`] for the key file, or a signing failure.
    pub fn sign(
        &self,
        id: &str,
        message: &[u8],
        passphrase: Option<&SecretString>,
    ) -> Result<String> {
        let entry = self.get(id).ok_or(CoreError::NoSuchIdentity)?;
        let openssh = crate::identity::load_text_maybe_encrypted(&self.path_for(entry), passphrase)?;
        super::sign_detached(&openssh, message, super::NAMESPACE)
    }

    fn next_id(&self) -> String {
        let mut n = self.index.entries.len() + 1;
        loop {
            let candidate = format!("signing-{n:03}");
            if !self.index.entries.iter().any(|e| e.id == candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(io_at(&self.root))?;
        let path = self.root.join("signing_keys.json");
        let json = serde_json::to_string_pretty(&self.index)?;
        let tmp = crate::encrypt::sibling_temp(&path);
        std::fs::write(&tmp, json).map_err(io_at(&tmp))?;
        std::fs::rename(&tmp, &path).map_err(io_at(&path))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED_KEY: &str = include_str!("../../tests/fixtures/sshsig_ed25519_key");
    const RSA_KEY: &str = include_str!("../../tests/fixtures/sshsig_rsa_key");

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join("agepony-signing-store").join(name);
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn import_stores_public_metadata_and_signs() {
        let root = scratch("import-sign");
        let mut store = SigningStore::open(&root).expect("open");
        let entry = store.import("Laptop SSH", ED_KEY, None, None).expect("import");
        assert_eq!(entry.kind, SigningKind::Ed25519);
        assert!(entry.public_line.starts_with("ssh-ed25519 "));
        assert!(entry.fingerprint.starts_with("SHA256:"));
        assert!(!entry.encrypted);

        // The index never contains the private key.
        let index = std::fs::read_to_string(root.join("signing_keys.json")).expect("index");
        assert!(!index.contains("PRIVATE KEY"), "index leaked a private key");

        // It can sign, and the signature verifies.
        let sig = store.sign(&entry.id, b"hello", None).expect("sign");
        let v = super::super::verify_detached(sig.as_bytes(), b"hello", super::super::NAMESPACE)
            .expect("verify");
        assert!(v.valid, "{:?}", v.reason);
    }

    #[test]
    fn rsa_key_imports_and_signs() {
        let root = scratch("rsa");
        let mut store = SigningStore::open(&root).expect("open");
        let entry = store.import("RSA key", RSA_KEY, None, None).expect("import");
        assert_eq!(entry.kind, SigningKind::Rsa);
        let sig = store.sign(&entry.id, b"data", None).expect("sign");
        assert!(
            super::super::verify_detached(sig.as_bytes(), b"data", super::super::NAMESPACE)
                .expect("verify")
                .valid
        );
    }

    #[test]
    fn a_protected_key_needs_its_passphrase_to_sign() {
        let root = scratch("protected");
        let mut store = SigningStore::open(&root).expect("open");
        let pass = SecretString::from("open sesame");
        let entry = store
            .import("Locked", ED_KEY, None, Some(&pass))
            .expect("import");
        assert!(entry.encrypted);

        assert!(matches!(
            store.sign(&entry.id, b"x", None),
            Err(CoreError::PassphraseRequired)
        ));
        assert!(store.sign(&entry.id, b"x", Some(&pass)).is_ok());

        // Reopen from disk and it still signs with the passphrase.
        let reopened = SigningStore::open(&root).expect("reopen");
        assert!(reopened.sign(&entry.id, b"x", Some(&pass)).is_ok());
    }

    #[test]
    fn delete_removes_the_key_file() {
        let root = scratch("delete");
        let mut store = SigningStore::open(&root).expect("open");
        let entry = store.import("Temp", ED_KEY, None, None).expect("import");
        let path = store.path_for(&entry);
        assert!(path.exists());
        store.delete(&entry.id).expect("delete");
        assert!(!path.exists(), "key file must be gone");
        assert!(store.entries().is_empty());
    }

    #[test]
    fn duplicate_labels_are_refused() {
        let root = scratch("dupes");
        let mut store = SigningStore::open(&root).expect("open");
        store.import("Same", ED_KEY, None, None).expect("first");
        assert!(matches!(
            store.import("Same", RSA_KEY, None, None),
            Err(CoreError::DuplicateLabel(_))
        ));
    }

    #[test]
    fn an_age_identity_is_not_a_signing_key() {
        let root = scratch("not-ssh");
        let mut store = SigningStore::open(&root).expect("open");
        let age_identity = include_str!("../../tests/fixtures/x25519_identity.txt");
        assert!(matches!(
            store.import("Nope", age_identity, None, None),
            Err(CoreError::InvalidIdentity)
        ));
    }
}
