//! The recipient book: named recipients, public key material only.
//!
//! Nothing secret is ever written to this file. That is a deliberate invariant,
//! not an implementation detail, so the book can be synced, backed up or
//! emailed without thinking about it.

use crate::error::{Result, io_at};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One entry in the recipient book.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Human label, e.g. "Ada's laptop". This is the name-labels feature.
    pub name: String,
    /// The recipient string. Public key material only.
    pub recipient: String,
    /// Optional free-text note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// RFC 3339 timestamp, as a string so the book has no time crate dependency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<String>,
    /// Set when this entry is the public half of an identity held on this
    /// machine, naming that identity.
    ///
    /// This is what makes "encrypt to myself" work without the user copying
    /// their own key around, and it is why deleting an identity can take its
    /// recipient with it. A recipient left behind after its private key is gone
    /// is worse than no recipient at all: it still encrypts, and the result is
    /// a file nobody can ever open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
}

impl Entry {
    /// Whether this recipient belongs to an identity on this machine.
    #[must_use]
    pub fn is_own(&self) -> bool {
        self.identity_id.is_some()
    }
}

/// The book itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Book {
    /// Format version, so a future change is detectable rather than silent.
    #[serde(default = "one")]
    pub version: u32,
    /// The entries.
    #[serde(default)]
    pub entries: Vec<Entry>,
}

const fn one() -> u32 {
    1
}

/// How an identity's own entry is labelled in the book.
///
/// Public so tests can assert the book actually follows the identity's label —
/// a rename that updated the recipient but not the name used to slip through
/// the invariant check unnoticed.
#[must_use]
pub fn self_name(label: &str) -> String {
    format!("{} (this machine)", label.trim())
}

/// `name`, or `name 2`, `name 3` … until it is not in `taken`.
fn unique_among(name: &str, taken: &[&str]) -> String {
    if !taken.contains(&name) {
        return name.to_owned();
    }
    for n in 2..10_000 {
        let candidate = format!("{name} {n}");
        if !taken.contains(&candidate.as_str()) {
            return candidate;
        }
    }
    name.to_owned()
}

impl Book {
    /// Load a book, returning an empty one if the file does not exist.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::Io`] if the file exists but cannot be read,
    /// [`crate::CoreError::CorruptBook`] if it is not valid JSON.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                version: 1,
                entries: Vec::new(),
            });
        }
        let text = std::fs::read_to_string(path).map_err(io_at(path))?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Save the book atomically.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::Io`] on a filesystem failure.
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

    /// Add an entry, validating the recipient string first.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::InvalidRecipient`] if the string is not a recipient
    /// we understand, or [`crate::CoreError::DuplicateLabel`] if the name is
    /// already taken.
    pub fn add(&mut self, name: &str, recipient: &str, note: Option<String>) -> Result<()> {
        let name = name.trim();
        let recipient = recipient.trim();

        // Parse before storing. A book full of strings that turn out not to be
        // recipients is worse than no book: the failure surfaces at encrypt
        // time, when the user has already picked the file and pressed the
        // button.
        crate::recipient::parse(recipient)?;

        if name.is_empty() {
            return Err(crate::CoreError::DuplicateLabel(String::new()));
        }
        if self.entries.iter().any(|e| e.name == name) {
            return Err(crate::CoreError::DuplicateLabel(name.to_owned()));
        }

        self.entries.push(Entry {
            name: name.to_owned(),
            recipient: recipient.to_owned(),
            note,
            added: Some(crate::clock::now_rfc3339()),
            identity_id: None,
        });
        Ok(())
    }

    /// Replace an entry, found by its current name.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::InvalidRecipient`] for a bad recipient string,
    /// [`crate::CoreError::NoSuchIdentity`] if `current_name` is not present,
    /// or [`crate::CoreError::DuplicateLabel`] if the new name collides.
    pub fn update(
        &mut self,
        current_name: &str,
        name: &str,
        recipient: &str,
        note: Option<String>,
    ) -> Result<()> {
        let name = name.trim();
        let recipient = recipient.trim();
        crate::recipient::parse(recipient)?;

        if self
            .entries
            .iter()
            .any(|e| e.name == name && e.name != current_name)
        {
            return Err(crate::CoreError::DuplicateLabel(name.to_owned()));
        }

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.name == current_name)
            .ok_or(crate::CoreError::NoSuchIdentity)?;
        entry.name = name.to_owned();
        entry.recipient = recipient.to_owned();
        entry.note = note;
        Ok(())
    }

    /// Remove an entry by name. Returns whether anything was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() != before
    }

    /// Import recipients from an age recipients file.
    ///
    /// The format is one recipient per line with `#` comments, which is what
    /// `age -R` reads. AgePony writes the name as a `# name: …` comment on the
    /// line above, so a book exported here and re-imported keeps its labels,
    /// while a plain recipients file from anywhere else still works — those
    /// entries just get a generated name.
    ///
    /// Returns the number of entries added. Duplicates and unparseable lines
    /// are skipped rather than failing the whole import.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::Io`] if the file cannot be read.
    pub fn import_recipients_file(&mut self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path).map_err(io_at(path))?;
        let mut added = 0;
        let mut pending_name: Option<String> = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix('#') {
                if let Some(name) = rest.trim().strip_prefix("name:") {
                    pending_name = Some(name.trim().to_owned());
                }
                continue;
            }

            let name = pending_name
                .take()
                .filter(|n| !n.is_empty() && !self.entries.iter().any(|e| &e.name == n))
                .unwrap_or_else(|| self.unused_name("Imported"));

            if self.entries.iter().any(|e| e.recipient == line) {
                continue;
            }
            if self.add(&name, line, None).is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Export the book as an age recipients file, preserving names as comments.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::Io`] if the file cannot be written.
    pub fn export_recipients_file(&self, path: &Path) -> Result<()> {
        let mut out = String::from("# AgePony recipients\n");
        for e in &self.entries {
            out.push_str(&format!("\n# name: {}\n", e.name));
            if let Some(note) = e.note.as_deref().filter(|n| !n.trim().is_empty()) {
                out.push_str(&format!("# note: {note}\n"));
            }
            out.push_str(&e.recipient);
            out.push('\n');
        }
        std::fs::write(path, out).map_err(io_at(path))
    }

    fn unused_name(&self, stem: &str) -> String {
        let mut n = 1;
        loop {
            let candidate = format!("{stem} {n}");
            if !self.entries.iter().any(|e| e.name == candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Create or update the book entry belonging to an identity.
    ///
    /// Matches on the identity id, not the name, so renaming an identity moves
    /// its entry rather than leaving a stale one behind.
    ///
    /// # Errors
    ///
    /// [`crate::CoreError::InvalidRecipient`] if the recipient does not parse,
    /// which would mean the store handed us something impossible.
    pub fn upsert_own(&mut self, identity_id: &str, name: &str, recipient: &str) -> Result<()> {
        crate::recipient::parse(recipient)?;

        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.identity_id.as_deref() == Some(identity_id))
        {
            existing.name = self_name(name);
            existing.recipient = recipient.to_owned();
            return Ok(());
        }

        // A manual entry may already hold this recipient — someone pasted their
        // own key in before generating it here. Adopt it rather than duplicate.
        if let Some(existing) = self.entries.iter_mut().find(|e| e.recipient == recipient) {
            existing.identity_id = Some(identity_id.to_owned());
            existing.name = self_name(name);
            return Ok(());
        }

        let taken: Vec<&str> = self.entries.iter().map(|e| e.name.as_str()).collect();
        let name = unique_among(&self_name(name), &taken);

        self.entries.push(Entry {
            name,
            recipient: recipient.to_owned(),
            note: None,
            added: Some(crate::clock::now_rfc3339()),
            identity_id: Some(identity_id.to_owned()),
        });
        Ok(())
    }

    /// Drop the entry belonging to `identity_id`, if there is one.
    ///
    /// Returns the name of what was removed.
    pub fn forget_identity(&mut self, identity_id: &str) -> Option<String> {
        let position = self
            .entries
            .iter()
            .position(|e| e.identity_id.as_deref() == Some(identity_id))?;
        Some(self.entries.remove(position).name)
    }

    /// Entries sorted for display: this machine's own recipients first, then
    /// everything else, each group alphabetically.
    ///
    /// Own keys go on top because "encrypt to myself" is the single most
    /// frequent thing anyone does with a recipient list.
    #[must_use]
    pub fn sorted(&self) -> Vec<&Entry> {
        let mut out: Vec<&Entry> = self.entries.iter().collect();
        out.sort_by(|a, b| {
            b.is_own()
                .cmp(&a.is_own())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        out
    }

    /// Case-insensitive substring search over name, recipient and note.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return self.sorted();
        }
        self.sorted()
            .into_iter()
            .filter(|e| {
                e.name.to_lowercase().contains(&q)
                    || e.recipient.to_lowercase().contains(&q)
                    || e.note
                        .as_deref()
                        .is_some_and(|n| n.to_lowercase().contains(&q))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Book {
        Book {
            version: 1,
            entries: vec![
                Entry {
                    name: "Ada".into(),
                    recipient: "age1ada".into(),
                    note: Some("work laptop".into()),
                    added: None,
                    identity_id: None,
                },
                Entry {
                    name: "Grace".into(),
                    recipient: "age1grace".into(),
                    note: None,
                    added: None,
                    identity_id: None,
                },
            ],
        }
    }

    #[test]
    fn search_is_case_insensitive_and_covers_notes() {
        let b = sample();
        assert_eq!(b.search("ADA").len(), 1);
        assert_eq!(b.search("laptop").len(), 1);
        assert_eq!(b.search("").len(), 2);
        assert_eq!(b.search("nobody").len(), 0);
    }

    #[test]
    fn round_trips_through_json() {
        let b = sample();
        let json = serde_json::to_string(&b).expect("serialize");
        let back: Book = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.entries, b.entries);
    }

    #[test]
    fn add_rejects_a_string_that_is_not_a_recipient() {
        let mut b = Book::default();
        assert!(b.add("Nope", "not a recipient", None).is_err());
        assert!(b.entries.is_empty());
    }

    #[test]
    fn add_rejects_a_duplicate_name() {
        let mut b = Book::default();
        let r = age::x25519::Identity::generate().to_public().to_string();
        b.add("Ada", &r, None).expect("first");
        let other = age::x25519::Identity::generate().to_public().to_string();
        assert!(b.add("Ada", &other, None).is_err());
    }

    #[test]
    fn update_and_remove_work() {
        let mut b = Book::default();
        let r = age::x25519::Identity::generate().to_public().to_string();
        b.add("Ada", &r, None).expect("add");

        let r2 = age::x25519::Identity::generate().to_public().to_string();
        b.update("Ada", "Ada Lovelace", &r2, Some("new key".into()))
            .expect("update");
        assert_eq!(b.entries[0].name, "Ada Lovelace");
        assert_eq!(b.entries[0].recipient, r2);

        assert!(b.remove("Ada Lovelace"));
        assert!(!b.remove("Ada Lovelace"));
        assert!(b.entries.is_empty());
    }

    #[test]
    fn recipients_file_round_trips_with_names_intact() {
        let dir = std::env::temp_dir().join("agepony-book-export");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("recipients.txt");

        let mut b = Book::default();
        let r1 = age::x25519::Identity::generate().to_public().to_string();
        let r2 = crate::pq::Identity::generate()
            .expect("pq")
            .to_public()
            .expect("public")
            .to_string();
        b.add("Ada", &r1, Some("work laptop".into())).expect("add");
        b.add("Grace", &r2, None).expect("add");
        b.export_recipients_file(&path).expect("export");

        let mut fresh = Book::default();
        assert_eq!(fresh.import_recipients_file(&path).expect("import"), 2);
        assert_eq!(fresh.entries[0].name, "Ada");
        assert_eq!(fresh.entries[0].recipient, r1);
        assert_eq!(fresh.entries[1].name, "Grace");
        assert_eq!(fresh.entries[1].recipient, r2);

        // Re-importing the same file must not duplicate anything.
        assert_eq!(fresh.import_recipients_file(&path).expect("import"), 0);
        assert_eq!(fresh.entries.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plain_recipients_file_imports_with_generated_names() {
        let dir = std::env::temp_dir().join("agepony-book-plain");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plain.txt");

        let r1 = age::x25519::Identity::generate().to_public().to_string();
        let r2 = age::x25519::Identity::generate().to_public().to_string();
        std::fs::write(&path, format!("# a comment\n{r1}\n\n{r2}\n")).expect("write");

        let mut b = Book::default();
        assert_eq!(b.import_recipients_file(&path).expect("import"), 2);
        assert_eq!(b.entries[0].name, "Imported 1");
        assert_eq!(b.entries[1].name, "Imported 2");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upsert_own_creates_then_updates_rather_than_duplicating() {
        let mut b = Book::default();
        let r = age::x25519::Identity::generate().to_public().to_string();

        b.upsert_own("identity-001", "Laptop", &r).expect("create");
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.entries[0].name, "Laptop (this machine)");
        assert!(b.entries[0].is_own());

        // Renaming the identity moves the same entry.
        b.upsert_own("identity-001", "Work laptop", &r)
            .expect("update");
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.entries[0].name, "Work laptop (this machine)");
    }

    #[test]
    fn upsert_own_adopts_a_manual_entry_holding_the_same_key() {
        // Someone pasted their own recipient in by hand before generating it
        // here. Two entries for one key would be a confusing duplicate.
        let mut b = Book::default();
        let r = age::x25519::Identity::generate().to_public().to_string();
        b.add("My key", &r, None).expect("manual add");

        b.upsert_own("identity-001", "Laptop", &r).expect("adopt");
        assert_eq!(b.entries.len(), 1);
        assert!(b.entries[0].is_own());
    }

    #[test]
    fn forget_identity_removes_only_that_entry() {
        let mut b = Book::default();
        let mine = age::x25519::Identity::generate().to_public().to_string();
        let theirs = age::x25519::Identity::generate().to_public().to_string();
        b.upsert_own("identity-001", "Laptop", &mine).expect("own");
        b.add("Ada", &theirs, None).expect("manual");

        assert_eq!(
            b.forget_identity("identity-001").as_deref(),
            Some("Laptop (this machine)")
        );
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.entries[0].name, "Ada");
        assert!(b.forget_identity("identity-001").is_none());
    }

    #[test]
    fn own_recipients_sort_first() {
        let mut b = Book::default();
        let theirs = age::x25519::Identity::generate().to_public().to_string();
        let mine = age::x25519::Identity::generate().to_public().to_string();
        b.add("Aaron", &theirs, None).expect("manual");
        b.upsert_own("identity-001", "Zoe", &mine).expect("own");

        let sorted = b.sorted();
        assert!(sorted[0].is_own(), "own keys belong at the top");
        assert_eq!(sorted[1].name, "Aaron");
    }

    #[test]
    fn a_book_written_before_this_change_still_loads() {
        // identity_id is absent from older files; serde must default it.
        let json = r#"{"version":1,"entries":[{"name":"Ada","recipient":"age1ada"}]}"#;
        let b: Book = serde_json::from_str(json).expect("older book loads");
        assert_eq!(b.entries.len(), 1);
        assert!(!b.entries[0].is_own());
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let b = Book::load(Path::new("/nonexistent/agepony/book.json")).expect("empty book");
        assert!(b.entries.is_empty());
    }
}
