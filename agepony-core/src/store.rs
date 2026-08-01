//! The identity store.
//!
//! Identities live in the per-OS config directory, one file each, mode `0600`
//! on Unix. A JSON index alongside them records the label, the public recipient,
//! the kind and the creation date, so the Identities panel can list everything
//! without decrypting anything.
//!
//! ```text
//! <config>/AgePony/
//! ├── identities.json          index: labels, recipients, dates, active
//! ├── recipients.json          the recipient book
//! └── identities/
//!     ├── <id>.txt             plain identity file
//!     └── <id>.age             passphrase-protected identity file
//! ```
//!
//! **The index holds no key material.** A recipient is a public key; that is
//! the only key-shaped thing in it. That invariant is what makes the index safe
//! to back up, sync or read while debugging, and it is tested.

use crate::clock;
use crate::error::{CoreError, Result, io_at};
use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Which kind of identity an entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Classic X25519. Not quantum-safe.
    X25519,
    /// `mlkem768x25519`. Quantum-safe.
    PostQuantum,
}

impl Kind {
    /// Whether this identity is quantum-safe.
    #[must_use]
    pub fn is_post_quantum(self) -> bool {
        matches!(self, Kind::PostQuantum)
    }

    /// A short label for the UI.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Kind::X25519 => "classic",
            Kind::PostQuantum => "post-quantum",
        }
    }
}

/// One identity in the store. Public metadata only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Stable id, also the file stem.
    pub id: String,
    /// Human label, e.g. "Laptop".
    pub label: String,
    /// The public recipient string. Safe to display and copy.
    pub recipient: String,
    /// Classic or post-quantum.
    pub kind: Kind,
    /// RFC 3339 creation date, UTC.
    pub created: String,
    /// Whether the identity file is passphrase protected.
    pub encrypted: bool,
}

impl Entry {
    /// The file name for this entry's key material.
    #[must_use]
    pub fn file_name(&self) -> String {
        if self.encrypted {
            format!("{}.age", self.id)
        } else {
            format!("{}.txt", self.id)
        }
    }
}

/// The on-disk index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Index {
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    entries: Vec<Entry>,
    #[serde(default)]
    active: Option<String>,
}

const fn one() -> u32 {
    1
}

/// The identity store, rooted at a directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    index: Index,
}

impl Store {
    /// Open the store at `root`, creating an empty one if nothing is there.
    ///
    /// # Errors
    ///
    /// [`CoreError::Io`] if the index exists but cannot be read,
    /// [`CoreError::CorruptBook`] if it is not valid JSON.
    pub fn open(root: &Path) -> Result<Self> {
        let index_path = root.join("identities.json");
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

    /// Every entry, newest first.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.index.entries
    }

    /// The id of the active identity, if one is set.
    #[must_use]
    pub fn active_id(&self) -> Option<&str> {
        self.index.active.as_deref()
    }

    /// The active entry, if one is set and still present.
    #[must_use]
    pub fn active(&self) -> Option<&Entry> {
        let id = self.index.active.as_deref()?;
        self.index.entries.iter().find(|e| e.id == id)
    }

    /// Look an entry up by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.index.entries.iter().find(|e| e.id == id)
    }

    /// The path to an entry's key material.
    #[must_use]
    pub fn path_for(&self, entry: &Entry) -> PathBuf {
        self.root.join("identities").join(entry.file_name())
    }

    /// Generate a new identity and store it.
    ///
    /// Supplying a passphrase encrypts the identity file using age's own
    /// passphrase encryption, so it stays readable by `age -d`.
    ///
    /// # Errors
    ///
    /// [`CoreError::DuplicateLabel`] if the label is taken, or any I/O or
    /// crypto failure from writing the file.
    pub fn generate(
        &mut self,
        label: &str,
        kind: Kind,
        passphrase: Option<&SecretString>,
    ) -> Result<Entry> {
        let (recipient, secret): (String, Zeroizing<String>) = match kind {
            Kind::X25519 => {
                use age::secrecy::ExposeSecret as _;
                let id = crate::identity::generate_x25519();
                let recipient = id.to_public().to_string();
                let secret = Zeroizing::new(id.to_string().expose_secret().to_string());
                (recipient, secret)
            }
            Kind::PostQuantum => {
                let id = crate::identity::generate_pq()?;
                (id.to_public()?.to_string(), id.to_bech32()?)
            }
        };
        self.insert(label, &recipient, &secret, kind, passphrase)
    }

    /// Import an identity from an existing file.
    ///
    /// The file may be plain or passphrase protected; `source_passphrase`
    /// unlocks it. `passphrase` protects the imported copy, independently.
    ///
    /// # Errors
    ///
    /// [`CoreError::PassphraseRequired`] if the source is locked and no
    /// passphrase was given, [`CoreError::NoIdentities`] if the file holds
    /// nothing usable, or [`CoreError::DuplicateLabel`].
    pub fn import(
        &mut self,
        label: &str,
        source: &Path,
        source_passphrase: Option<&SecretString>,
        passphrase: Option<&SecretString>,
    ) -> Result<Entry> {
        let bytes = std::fs::read(source).map_err(io_at(source))?;

        let text: Zeroizing<String> = if crate::identity::looks_encrypted(&bytes) {
            let pass = source_passphrase.ok_or(CoreError::PassphraseRequired)?;
            let loaded = crate::identity::load_file_maybe_encrypted(source, Some(pass))?;
            drop(loaded);
            // Re-read as text via the same path so we keep the original file's
            // comments and ordering rather than re-serialising parsed keys.
            Zeroizing::new(read_decrypted_text(source, pass)?)
        } else {
            Zeroizing::new(String::from_utf8(bytes).map_err(|_| CoreError::InvalidIdentity)?)
        };

        // Validate, and work out what kind and recipient this is.
        let (kind, recipient) = describe_identity_text(&text)?;
        let secret = Zeroizing::new(first_secret_line(&text)?);
        self.insert(label, &recipient, &secret, kind, passphrase)
    }

    /// Install an identity that arrived from another device.
    ///
    /// The key material goes straight from the in-memory [`Ported`] into this
    /// store's own `0600` file; it is never written anywhere else.
    ///
    /// [`Ported`]: crate::porting::Ported
    ///
    /// # Errors
    ///
    /// [`CoreError::DuplicateLabel`] if the label is taken, or any failure
    /// writing the key file.
    pub fn install_ported(
        &mut self,
        ported: &crate::porting::Ported,
        label: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<Entry> {
        let secret = Zeroizing::new(first_secret_line(ported.text())?);
        self.insert(label, &ported.recipient, &secret, ported.kind, passphrase)
    }

    /// Whether the store already holds an identity with this recipient.
    ///
    /// Porting the same phone twice is an easy mistake; this is what lets the
    /// UI say so rather than quietly making a duplicate.
    #[must_use]
    pub fn find_by_recipient(&self, recipient: &str) -> Option<&Entry> {
        self.index.entries.iter().find(|e| e.recipient == recipient)
    }

    fn insert(
        &mut self,
        label: &str,
        recipient: &str,
        secret: &str,
        kind: Kind,
        passphrase: Option<&SecretString>,
    ) -> Result<Entry> {
        let label = label.trim();
        if label.is_empty() {
            return Err(CoreError::DuplicateLabel(String::new()));
        }
        if self.index.entries.iter().any(|e| e.label == label) {
            return Err(CoreError::DuplicateLabel(label.to_owned()));
        }

        let entry = Entry {
            id: self.next_id(),
            label: label.to_owned(),
            recipient: recipient.to_owned(),
            kind,
            created: clock::now_rfc3339(),
            encrypted: passphrase.is_some(),
        };

        let body = crate::identity::identity_file_body(recipient, secret);
        let path = self.path_for(&entry);
        match passphrase {
            Some(p) => crate::identity::save_encrypted_identity_file(&path, &body, p)?,
            None => crate::identity::save_identity_file(&path, &body)?,
        }

        self.index.entries.insert(0, entry.clone());
        if self.index.active.is_none() {
            self.index.active = Some(entry.id.clone());
        }
        self.save()?;
        Ok(entry)
    }

    /// Rename an identity.
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

    /// Set the active identity, the one Decrypt reaches for by default.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSuchIdentity`] if there is no such entry.
    pub fn set_active(&mut self, id: &str) -> Result<()> {
        if !self.index.entries.iter().any(|e| e.id == id) {
            return Err(CoreError::NoSuchIdentity);
        }
        self.index.active = Some(id.to_owned());
        self.save()
    }

    /// Delete an identity and its key material.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSuchIdentity`], or [`CoreError::Io`] if the key file
    /// cannot be removed — in which case the index is left untouched, so the
    /// store never claims to have deleted something it did not.
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
        if self.index.active.as_deref() == Some(id) {
            self.index.active = self.index.entries.first().map(|e| e.id.clone());
        }
        self.save()
    }

    /// Copy an identity's file out to `destination`, verbatim.
    ///
    /// An encrypted identity is exported still encrypted; this never decrypts
    /// as a side effect of exporting.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSuchIdentity`] or [`CoreError::Io`].
    pub fn export(&self, id: &str, destination: &Path) -> Result<()> {
        let entry = self.get(id).ok_or(CoreError::NoSuchIdentity)?;
        let source = self.path_for(entry);
        let bytes = std::fs::read(&source).map_err(io_at(&source))?;
        std::fs::write(destination, bytes).map_err(io_at(destination))?;
        crate::identity::set_owner_only(destination)
    }

    /// Load the usable `age` identities for an entry.
    ///
    /// # Errors
    ///
    /// [`CoreError::PassphraseRequired`] if it is locked and no passphrase was
    /// given, or [`CoreError::Decrypt`] if the passphrase is wrong.
    pub fn load(
        &self,
        id: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<Vec<Box<dyn age::Identity + Send + Sync>>> {
        let entry = self.get(id).ok_or(CoreError::NoSuchIdentity)?;
        crate::identity::load_file_maybe_encrypted(&self.path_for(entry), passphrase)
    }

    fn next_id(&self) -> String {
        // Sequential rather than random: the id is a file stem, not a secret,
        // and a predictable one is far easier to reason about when someone is
        // staring at the config directory trying to work out what is what.
        let mut n = self.index.entries.len() + 1;
        loop {
            let candidate = format!("identity-{n:03}");
            if !self.index.entries.iter().any(|e| e.id == candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(io_at(&self.root))?;
        let path = self.root.join("identities.json");
        let json = serde_json::to_string_pretty(&self.index)?;
        let tmp = crate::encrypt::sibling_temp(&path);
        std::fs::write(&tmp, json).map_err(io_at(&tmp))?;
        std::fs::rename(&tmp, &path).map_err(io_at(&path))?;
        Ok(())
    }
}

fn read_decrypted_text(path: &Path, passphrase: &SecretString) -> Result<String> {
    let bytes = std::fs::read(path).map_err(io_at(path))?;
    let armored = age::armor::ArmoredReader::new(&bytes[..]);
    let decryptor = age::Decryptor::new(armored)?;
    let identity = crate::passphrase::identity(passphrase.clone());
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    let mut out = Zeroizing::new(Vec::new());
    std::io::Read::read_to_end(&mut reader, &mut out)?;
    String::from_utf8(out.to_vec()).map_err(|_| CoreError::InvalidIdentity)
}

/// Work out the kind and public recipient of an identity file's contents.
///
/// # Errors
///
/// [`CoreError::NoIdentities`] if no usable key line is present.
pub fn describe_identity_text(text: &str) -> Result<(Kind, String)> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_uppercase().starts_with(crate::pq::IDENTITY_HRP) {
            let id = crate::pq::Identity::from_bech32(line)?;
            return Ok((Kind::PostQuantum, id.to_public()?.to_string()));
        }
        if let Ok(id) = line.parse::<age::x25519::Identity>() {
            return Ok((Kind::X25519, id.to_public().to_string()));
        }
    }
    Err(CoreError::NoIdentities)
}

fn first_secret_line(text: &str) -> Result<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .ok_or(CoreError::NoIdentities)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join("agepony-store").join(name);
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn generate_stores_and_reloads() {
        let root = scratch("generate");
        let mut store = Store::open(&root).expect("open");
        assert!(store.entries().is_empty());

        let entry = store
            .generate("Laptop", Kind::X25519, None)
            .expect("generate");
        assert_eq!(entry.label, "Laptop");
        assert!(entry.recipient.starts_with("age1"));
        assert!(!entry.encrypted);

        // The first identity added becomes active automatically.
        assert_eq!(store.active_id(), Some(entry.id.as_str()));

        let reopened = Store::open(&root).expect("reopen");
        assert_eq!(reopened.entries(), store.entries());
        assert_eq!(reopened.active_id(), Some(entry.id.as_str()));

        let ids = reopened.load(&entry.id, None).expect("load");
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn the_index_never_contains_key_material() {
        let root = scratch("no-secrets");
        let mut store = Store::open(&root).expect("open");
        store
            .generate("Classic", Kind::X25519, None)
            .expect("generate");
        store
            .generate("Quantum", Kind::PostQuantum, None)
            .expect("generate");

        let index = std::fs::read_to_string(root.join("identities.json")).expect("read index");
        assert!(!index.contains("AGE-SECRET-KEY-"), "index leaked a secret");
        assert!(
            index.contains("age1"),
            "index should hold public recipients"
        );
    }

    #[test]
    fn a_passphrase_protected_identity_needs_its_passphrase() {
        let root = scratch("encrypted");
        let mut store = Store::open(&root).expect("open");
        let pass = SecretString::from("open sesame");
        let entry = store
            .generate("Locked", Kind::X25519, Some(&pass))
            .expect("generate");
        assert!(entry.encrypted);

        assert!(matches!(
            store.load(&entry.id, None),
            Err(CoreError::PassphraseRequired)
        ));
        assert_eq!(store.load(&entry.id, Some(&pass)).expect("load").len(), 1);
    }

    #[test]
    fn duplicate_labels_are_refused() {
        let root = scratch("dupes");
        let mut store = Store::open(&root).expect("open");
        store.generate("Same", Kind::X25519, None).expect("first");
        assert!(matches!(
            store.generate("Same", Kind::X25519, None),
            Err(CoreError::DuplicateLabel(_))
        ));
    }

    #[test]
    fn deleting_the_active_identity_promotes_another() {
        let root = scratch("delete-active");
        let mut store = Store::open(&root).expect("open");
        let first = store.generate("One", Kind::X25519, None).expect("one");
        let second = store.generate("Two", Kind::X25519, None).expect("two");
        store.set_active(&second.id).expect("set active");

        let key_path = store.path_for(&second);
        assert!(key_path.exists());

        store.delete(&second.id).expect("delete");
        assert!(!key_path.exists(), "key material must be removed too");
        assert_eq!(store.active_id(), Some(first.id.as_str()));
        assert_eq!(store.entries().len(), 1);
    }

    #[test]
    fn export_of_an_encrypted_identity_stays_encrypted() {
        let root = scratch("export");
        let mut store = Store::open(&root).expect("open");
        let pass = SecretString::from("stay locked");
        let entry = store
            .generate("Locked", Kind::X25519, Some(&pass))
            .expect("generate");

        let out = root.join("exported.age");
        store.export(&entry.id, &out).expect("export");
        let bytes = std::fs::read(&out).expect("read");
        assert!(
            crate::identity::looks_encrypted(&bytes),
            "exporting must not decrypt"
        );
    }

    #[test]
    fn import_round_trips_both_kinds() {
        let root = scratch("import");
        let mut store = Store::open(&root).expect("open");

        for (label, kind) in [
            ("Imported classic", Kind::X25519),
            ("Imported pq", Kind::PostQuantum),
        ] {
            let mut source_store = Store::open(&scratch(&format!("source-{label}"))).expect("open");
            let made = source_store
                .generate("Source", kind, None)
                .expect("generate");
            let source = source_store.path_for(&made);

            let entry = store.import(label, &source, None, None).expect("import");
            assert_eq!(entry.kind, kind);
            assert_eq!(entry.recipient, made.recipient);
            assert_eq!(store.load(&entry.id, None).expect("load").len(), 1);
        }
    }

    #[test]
    fn renaming_rejects_a_taken_label_but_allows_a_no_op() {
        let root = scratch("rename");
        let mut store = Store::open(&root).expect("open");
        let a = store.generate("Alpha", Kind::X25519, None).expect("a");
        store.generate("Beta", Kind::X25519, None).expect("b");

        assert!(matches!(
            store.rename(&a.id, "Beta"),
            Err(CoreError::DuplicateLabel(_))
        ));
        store
            .rename(&a.id, "Alpha")
            .expect("renaming to itself is fine");
        store.rename(&a.id, "Gamma").expect("rename");
        assert_eq!(store.get(&a.id).expect("entry").label, "Gamma");
    }
}
