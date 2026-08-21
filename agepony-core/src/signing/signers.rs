//! The trusted-signers list — AgePony's counterpart of Android's
//! `StoredSigner`/vault signers, and the desktop equivalent of the recipient
//! [`crate::book::Book`], but for verification instead of encryption.
//!
//! A trusted signer is an SSH public key the user recognises, under a name
//! (principal). When a detached signature verifies, the signer's public-key wire
//! blob is matched against this list to put a name on it. The list round-trips
//! through the OpenSSH `allowed_signers` format (see [`super::allowed_signers`]),
//! so a list built in the app drops straight onto a machine's command line and
//! back.
//!
//! Everything here is public key material, so `signers.json` is safe to sync or
//! back up, exactly like the recipient book.

use crate::error::{CoreError, Result, io_at};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Where a trusted signer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignerSource {
    /// Pasted as an SSH public-key line.
    PasteKey,
    /// Imported from an `allowed_signers` file.
    ImportAllowedSigners,
    /// Promoted from a recipient.
    FromRecipient,
    /// Added from a verification badge ("trust this unknown signer").
    FromVerification,
}

/// One trusted signer. Public key material only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSigner {
    /// Stable id.
    pub id: String,
    /// Principal / display name (e.g. `alice@example.com`).
    pub name: String,
    /// Key algorithm, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// The SSH public-key wire blob, Base64 — the exact bytes carried in a
    /// signature, so matching is a direct equality check.
    pub public_wire_b64: String,
    /// An optional comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Where it came from.
    pub source: SignerSource,
    /// RFC 3339 creation date, UTC.
    pub created: String,
}

impl StoredSigner {
    /// The public key as raw SSH wire bytes, or `None` if the base64 is invalid.
    #[must_use]
    pub fn public_wire(&self) -> Option<Vec<u8>> {
        BASE64.decode(self.public_wire_b64.as_bytes()).ok()
    }

    /// The `SHA256:…` fingerprint, or `None` if the stored blob is invalid.
    #[must_use]
    pub fn fingerprint(&self) -> Option<String> {
        super::fingerprint(&self.public_wire()?).ok()
    }

    /// One `allowed_signers` entry for this signer, for export.
    #[must_use]
    pub fn to_allowed_signer(
        &self,
        namespace_restricted: bool,
    ) -> super::allowed_signers::AllowedSigner {
        super::allowed_signers::AllowedSigner {
            principals: vec![self.name.clone()],
            options: namespace_restricted.then(|| format!("namespaces=\"{}\"", super::NAMESPACE)),
            key_type: self.key_type.clone(),
            key_base64: self.public_wire_b64.clone(),
            comment: self.comment.clone(),
        }
    }
}

/// The trusted-signers list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Signers {
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    signers: Vec<StoredSigner>,
}

const fn one() -> u32 {
    1
}

impl Signers {
    /// Load the list from `path`, or an empty list if the file is absent.
    ///
    /// # Errors
    ///
    /// [`CoreError::Io`] if it exists but cannot be read, or
    /// [`CoreError::CorruptBook`] if it is not valid JSON.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(io_at(path))?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Save the list to `path`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Io`] on a filesystem failure.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io_at(dir))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = crate::encrypt::sibling_temp(path);
        std::fs::write(&tmp, json).map_err(io_at(&tmp))?;
        std::fs::rename(&tmp, path).map_err(io_at(path))?;
        Ok(())
    }

    /// Every signer.
    #[must_use]
    pub fn all(&self) -> &[StoredSigner] {
        &self.signers
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }

    /// The signer whose key matches `wire`, if any. This is the trust check the
    /// verifier runs against a valid-but-unknown signature.
    #[must_use]
    pub fn matching(&self, wire: &[u8]) -> Option<&StoredSigner> {
        self.signers
            .iter()
            .find(|s| s.public_wire().as_deref() == Some(wire))
    }

    /// Add a signer from an SSH public-key line (`keytype base64 [comment]`)
    /// under `name`. Returns the new signer, or an error if the line is not a
    /// recognised SSH public key.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidRecipient`] if the line does not parse.
    pub fn add_from_public_line(
        &mut self,
        name: &str,
        ssh_public_key_line: &str,
        source: SignerSource,
    ) -> Result<StoredSigner> {
        let signer =
            super::allowed_signers::make_signer(&[name.to_owned()], ssh_public_key_line, false)
                .ok_or_else(|| CoreError::InvalidRecipient(ssh_public_key_line.to_owned()))?;
        self.push_from_allowed(&signer, source)
    }

    /// Add a signer from a public-key wire blob (from a verification verdict).
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidSignature`] if `wire` is not a valid SSH public key.
    pub fn add_from_wire(
        &mut self,
        name: &str,
        wire: &[u8],
        source: SignerSource,
    ) -> Result<StoredSigner> {
        let public =
            ssh_key::PublicKey::from_bytes(wire).map_err(|_| CoreError::InvalidSignature)?;
        let signer = StoredSigner {
            id: self.next_id(),
            name: name.trim().to_owned(),
            key_type: public.algorithm().as_str().to_owned(),
            public_wire_b64: BASE64.encode(wire),
            comment: None,
            source,
            created: crate::clock::now_rfc3339(),
        };
        self.signers.insert(0, signer.clone());
        Ok(signer)
    }

    /// Import every entry of an `allowed_signers` file body. Returns how many
    /// new signers were added (duplicates by key are skipped).
    pub fn import_allowed_signers(&mut self, text: &str) -> usize {
        let mut added = 0;
        for entry in super::allowed_signers::parse(text) {
            if self
                .push_from_allowed(&entry, SignerSource::ImportAllowedSigners)
                .is_ok()
            {
                added += 1;
            }
        }
        added
    }

    /// Serialize the whole list as an `allowed_signers` file body.
    #[must_use]
    pub fn export_allowed_signers(&self, namespace_restricted: bool) -> String {
        let entries: Vec<_> = self
            .signers
            .iter()
            .map(|s| s.to_allowed_signer(namespace_restricted))
            .collect();
        super::allowed_signers::serialize(&entries)
    }

    /// Remove every trusted signer — part of the panic wipe.
    pub fn clear(&mut self) {
        self.signers.clear();
    }

    /// Remove a signer by id. Returns whether one was removed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.signers.len();
        self.signers.retain(|s| s.id != id);
        self.signers.len() != before
    }

    fn push_from_allowed(
        &mut self,
        entry: &super::allowed_signers::AllowedSigner,
        source: SignerSource,
    ) -> Result<StoredSigner> {
        let wire = entry
            .public_key_wire()
            .ok_or_else(|| CoreError::InvalidRecipient(entry.key_base64.clone()))?;
        // Skip a key already trusted, whatever name it is under.
        if let Some(existing) = self.matching(&wire) {
            return Ok(existing.clone());
        }
        let name = entry
            .principals
            .first()
            .cloned()
            .ok_or_else(|| CoreError::InvalidRecipient(entry.key_base64.clone()))?;
        let signer = StoredSigner {
            id: self.next_id(),
            name,
            key_type: entry.key_type.clone(),
            public_wire_b64: entry.key_base64.clone(),
            comment: entry.comment.clone(),
            source,
            created: crate::clock::now_rfc3339(),
        };
        self.signers.insert(0, signer.clone());
        Ok(signer)
    }

    fn next_id(&self) -> String {
        let mut n = self.signers.len() + 1;
        loop {
            let candidate = format!("signer-{n:03}");
            if !self.signers.iter().any(|s| s.id == candidate) {
                return candidate;
            }
            n += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPufhC9ET6WoSU5oEErYNpBN4bTw2ZUA4wiyIYIOPlU kevin@agepony";

    #[test]
    fn add_paste_and_match_by_wire() {
        let mut s = Signers::default();
        let added = s
            .add_from_public_line("kevin", ED_PUB, SignerSource::PasteKey)
            .expect("add");
        assert_eq!(added.name, "kevin");
        assert!(added.fingerprint().unwrap().starts_with("SHA256:"));
        let wire = added.public_wire().unwrap();
        assert_eq!(s.matching(&wire).map(|m| m.name.as_str()), Some("kevin"));
        assert!(s.matching(b"not a key").is_none());
    }

    #[test]
    fn a_key_is_not_added_twice() {
        let mut s = Signers::default();
        s.add_from_public_line("kevin", ED_PUB, SignerSource::PasteKey)
            .expect("add");
        s.add_from_public_line("kevin-again", ED_PUB, SignerSource::PasteKey)
            .expect("add");
        assert_eq!(s.all().len(), 1, "same key must not duplicate");
    }

    #[test]
    fn allowed_signers_round_trips_through_the_store() {
        let mut s = Signers::default();
        s.add_from_public_line("alice", ED_PUB, SignerSource::PasteKey)
            .expect("add");
        let exported = s.export_allowed_signers(true);
        assert!(exported.contains("namespaces=\"agepony\""));

        let mut imported = Signers::default();
        let n = imported.import_allowed_signers(&exported);
        assert_eq!(n, 1);
        assert_eq!(imported.all()[0].name, "alice");
        assert_eq!(
            imported.all()[0].public_wire_b64,
            s.all()[0].public_wire_b64
        );
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join("agepony-signers-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("signers.json");
        let mut s = Signers::default();
        s.add_from_public_line("kevin", ED_PUB, SignerSource::PasteKey)
            .expect("add");
        s.save(&path).expect("save");

        let loaded = Signers::load(&path).expect("load");
        assert_eq!(loaded.all(), s.all());
        // Public only: the file holds no private key material.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("PRIVATE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_deletes_by_id() {
        let mut s = Signers::default();
        let a = s
            .add_from_public_line("kevin", ED_PUB, SignerSource::PasteKey)
            .expect("add");
        assert!(s.remove(&a.id));
        assert!(s.is_empty());
        assert!(!s.remove(&a.id));
    }
}
