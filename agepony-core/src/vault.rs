//! Keeping the identity store and the recipient book consistent.
//!
//! The two are separate on disk for good reason — one holds key material, the
//! other holds nothing secret — but they are not independent. Every identity on
//! this machine has a public recipient, and that recipient belongs in the book,
//! or "encrypt a copy to myself" means copying your own key around by hand.
//!
//! The invariant is: **the book contains exactly one entry for every identity in
//! the store, and none for identities that no longer exist.**
//!
//! The second half matters as much as the first. A recipient left behind after
//! its private key has been deleted still encrypts perfectly well, and the
//! result is a file nobody can ever open. That is a worse failure than a missing
//! recipient, because it fails silently and much later.
//!
//! These are free functions rather than a `Vault` struct so the two halves stay
//! independently borrowable, which is what the UI wants.

use crate::book::Book;
use crate::error::Result;
use crate::porting::Ported;
use crate::store::{Entry, Kind, Store};
use age::secrecy::SecretString;
use std::path::Path;

/// Generate an identity and record its recipient.
///
/// # Errors
///
/// Whatever [`Store::generate`] returns.
pub fn generate(
    store: &mut Store,
    book: &mut Book,
    label: &str,
    kind: Kind,
    passphrase: Option<&SecretString>,
) -> Result<Entry> {
    let entry = store.generate(label, kind, passphrase)?;
    book.upsert_own(&entry.id, &entry.label, &entry.recipient)?;
    Ok(entry)
}

/// Import an identity from a file and record its recipient.
///
/// # Errors
///
/// Whatever [`Store::import`] returns.
pub fn import(
    store: &mut Store,
    book: &mut Book,
    label: &str,
    source: &Path,
    source_passphrase: Option<&SecretString>,
    passphrase: Option<&SecretString>,
) -> Result<Entry> {
    let entry = store.import(label, source, source_passphrase, passphrase)?;
    book.upsert_own(&entry.id, &entry.label, &entry.recipient)?;
    Ok(entry)
}

/// Install a ported identity and record its recipient.
///
/// # Errors
///
/// Whatever [`Store::install_ported`] returns.
pub fn install_ported(
    store: &mut Store,
    book: &mut Book,
    ported: &Ported,
    label: &str,
    passphrase: Option<&SecretString>,
) -> Result<Entry> {
    let entry = store.install_ported(ported, label, passphrase)?;
    book.upsert_own(&entry.id, &entry.label, &entry.recipient)?;
    Ok(entry)
}

/// Rename an identity, and its book entry with it.
///
/// # Errors
///
/// Whatever [`Store::rename`] returns.
pub fn rename(store: &mut Store, book: &mut Book, id: &str, label: &str) -> Result<()> {
    store.rename(id, label)?;
    if let Some(entry) = store.get(id) {
        book.upsert_own(&entry.id, &entry.label, &entry.recipient)?;
    }
    Ok(())
}

/// Delete an identity, and its book entry with it.
///
/// # Errors
///
/// Whatever [`Store::delete`] returns. The book is only touched once the
/// identity is actually gone, so a failed delete cannot strand the book.
pub fn delete(store: &mut Store, book: &mut Book, id: &str) -> Result<()> {
    store.delete(id)?;
    book.forget_identity(id);
    Ok(())
}

/// What [`reconcile`] had to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reconciled {
    /// Identities that had no entry and now do.
    pub added: usize,
    /// Entries whose identity no longer exists.
    pub removed: usize,
    /// Entries that existed but held a stale name or recipient.
    ///
    /// Counted separately because it used to be invisible: reconcile repaired
    /// a stale name and reported nothing, which made "reconcile is a no-op" a
    /// worthless assertion in tests. A drift that repairs itself silently is a
    /// drift nobody notices.
    pub updated: usize,
}

impl Reconciled {
    /// Whether anything at all changed.
    #[must_use]
    pub fn is_clean(self) -> bool {
        self.added == 0 && self.removed == 0 && self.updated == 0
    }
}

/// Bring the book into line with the store.
///
/// Call at startup. This is what upgrades a book written before identities were
/// linked to it, and what repairs the two if they are ever edited apart — a
/// hand-edited JSON file, a restore from backup, a half-finished operation.
///
/// Returns a summary of what it changed.
///
/// # Errors
///
/// [`crate::CoreError::InvalidRecipient`] only if the store holds a recipient
/// that does not parse, which would mean the index is corrupt.
pub fn reconcile(store: &Store, book: &mut Book) -> Result<Reconciled> {
    let mut out = Reconciled::default();

    for entry in store.entries() {
        let expected_name = crate::book::self_name(&entry.label);
        let existing = book
            .entries
            .iter()
            .find(|e| e.identity_id.as_deref() == Some(entry.id.as_str()));

        match existing {
            None => out.added += 1,
            Some(e) if e.name != expected_name || e.recipient != entry.recipient => {
                out.updated += 1;
            }
            Some(_) => {}
        }

        book.upsert_own(&entry.id, &entry.label, &entry.recipient)?;
    }

    let before = book.entries.len();
    book.entries.retain(|e| match e.identity_id.as_deref() {
        Some(id) => store.get(id).is_some(),
        None => true,
    });
    out.removed = before - book.entries.len();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join("agepony-vault").join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn generating_an_identity_makes_it_available_as_a_recipient() {
        // The whole point: generate a key, then be able to encrypt to yourself
        // without ever copying a string.
        let mut store = Store::open(&scratch("generate")).expect("open");
        let mut book = Book::default();

        let entry =
            generate(&mut store, &mut book, "Laptop", Kind::X25519, None).expect("generate");

        let found = book
            .entries
            .iter()
            .find(|e| e.recipient == entry.recipient)
            .expect("the new identity is in the book");
        assert!(found.is_own());
        assert_eq!(found.identity_id.as_deref(), Some(entry.id.as_str()));

        // And it parses as a recipient, so the encrypt path will accept it.
        crate::recipient::parse(&found.recipient).expect("usable recipient");
    }

    #[test]
    fn renaming_an_identity_renames_its_recipient() {
        let mut store = Store::open(&scratch("rename")).expect("open");
        let mut book = Book::default();
        let entry =
            generate(&mut store, &mut book, "Laptop", Kind::X25519, None).expect("generate");

        rename(&mut store, &mut book, &entry.id, "Work laptop").expect("rename");
        assert_eq!(book.entries.len(), 1, "renaming must not duplicate");
        assert!(book.entries[0].name.starts_with("Work laptop"));
    }

    #[test]
    fn deleting_an_identity_removes_its_recipient() {
        // The dangerous case. A recipient whose private key is gone still
        // encrypts, and produces a file that can never be opened.
        let mut store = Store::open(&scratch("delete")).expect("open");
        let mut book = Book::default();
        let entry =
            generate(&mut store, &mut book, "Laptop", Kind::X25519, None).expect("generate");
        book.add(
            "Ada",
            &age::x25519::Identity::generate().to_public().to_string(),
            None,
        )
        .expect("someone else");

        delete(&mut store, &mut book, &entry.id).expect("delete");

        assert!(
            !book.entries.iter().any(|e| e.recipient == entry.recipient),
            "a recipient must not outlive its private key"
        );
        assert_eq!(book.entries.len(), 1, "other people's keys are untouched");
    }

    #[test]
    fn reconcile_backfills_identities_that_predate_the_book_link() {
        // The upgrade path: identities generated before recipients were linked.
        let root = scratch("reconcile");
        let mut store = Store::open(&root).expect("open");
        let a = store.generate("One", Kind::X25519, None).expect("a");
        let b = store.generate("Two", Kind::PostQuantum, None).expect("b");

        let mut book = Book::default();
        let summary = reconcile(&store, &mut book).expect("reconcile");
        assert_eq!((summary.added, summary.removed, summary.updated), (2, 0, 0));
        assert_eq!(book.entries.len(), 2);
        assert!(book.entries.iter().all(crate::book::Entry::is_own));
        assert!(book.entries.iter().any(|e| e.recipient == a.recipient));
        assert!(book.entries.iter().any(|e| e.recipient == b.recipient));

        // Running it again changes nothing.
        assert!(reconcile(&store, &mut book).expect("again").is_clean());
        assert_eq!(book.entries.len(), 2);
    }

    #[test]
    fn reconcile_drops_recipients_whose_identity_is_gone() {
        let root = scratch("reconcile-stale");
        let mut store = Store::open(&root).expect("open");
        let mut book = Book::default();
        generate(&mut store, &mut book, "Ghost", Kind::X25519, None).expect("generate");

        // Simulate the store losing the identity behind the book's back --
        // a restore from an older backup, say.
        let ghost = store.entries()[0].id.clone();
        store.delete(&ghost).expect("delete behind the book's back");
        // (delete via the store directly leaves the book stale on purpose)
        book.upsert_own(
            &ghost,
            "Ghost",
            &age::x25519::Identity::generate().to_public().to_string(),
        )
        .expect("restore the stale entry");

        let summary = reconcile(&store, &mut book).expect("reconcile");
        assert_eq!(summary.removed, 1);
        assert!(book.entries.is_empty());
    }

    #[test]
    fn manual_recipients_survive_reconciliation() {
        let root = scratch("reconcile-manual");
        let store = Store::open(&root).expect("open");
        let mut book = Book::default();
        book.add(
            "Ada",
            &age::x25519::Identity::generate().to_public().to_string(),
            None,
        )
        .expect("manual");

        reconcile(&store, &mut book).expect("reconcile");
        assert_eq!(
            book.entries.len(),
            1,
            "other people's keys are not ours to remove"
        );
    }
}
