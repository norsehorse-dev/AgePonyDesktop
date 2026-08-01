//! Identity porting: moving an identity from a phone onto this machine.
//!
//! The flow, from section 7.5 of the plan:
//!
//! ```text
//! desktop                                phone
//! -------                                -----
//! show recipient + QR   ──────────────►  scan it
//!                                        encrypt its identity to that recipient
//! import the file       ◄──────────────  hand over the file
//! decrypt, install
//! ```
//!
//! No OTP, no server, no pairing ceremony. The desktop's own identity *is* the
//! channel: only the machine holding that private key can read what the phone
//! sends. Nothing here talks to a network, and nothing here is AgePony-specific
//! on the wire — the phone side is an ordinary age encryption to an ordinary
//! recipient.
//!
//! # The format
//!
//! The plaintext the phone encrypts is an age identity file with two optional
//! comment lines:
//!
//! ```text
//! # agepony-port: v1
//! # name: Phone key
//! AGE-SECRET-KEY-1QQQ…
//! ```
//!
//! Comments are ignored by every age implementation, so a file produced without
//! them still imports — the name just has to be typed on this end. The
//! ciphertext is a plain age file encrypted to the desktop recipient, binary or
//! armored; both are accepted.
//!
//! # Why this decrypts in memory
//!
//! [`decrypt_file`](crate::decrypt::decrypt_file) writes plaintext to disk,
//! which is right for a payload and wrong for a private key. Porting uses
//! [`decrypt_to_memory`](crate::decrypt::decrypt_to_memory) into a
//! [`Zeroizing`] buffer, so a ported identity goes from ciphertext straight
//! into the store's own `0600` file and exists nowhere else.

use crate::error::{CoreError, Result, io_at};
use crate::store::Kind;
use std::path::Path;
use zeroize::Zeroizing;

/// Marks a plaintext as an AgePony port payload. Optional, and only a hint.
pub const MARKER: &str = "# agepony-port: v1";

/// Comment prefix carrying the identity's label from the sending device.
pub const NAME_PREFIX: &str = "# name:";

/// The suggested file extension for a ported identity.
pub const EXTENSION: &str = "age";

/// Build the plaintext a sending device should encrypt.
///
/// The desktop does not currently send identities anywhere, but this is here so
/// the two halves are defined in one place, and it is what the round-trip test
/// exercises.
#[must_use]
pub fn payload(label: &str, secret: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{MARKER}\n{NAME_PREFIX} {label}\n{secret}\n"))
}

/// An identity that arrived from another device, decrypted but not yet stored.
pub struct Ported {
    /// The label the sending device suggested, if it sent one.
    pub suggested_label: Option<String>,
    /// What kind of identity arrived.
    pub kind: Kind,
    /// Its public recipient. Safe to display.
    pub recipient: String,
    /// The identity file text. Secret.
    text: Zeroizing<String>,
}

impl Ported {
    /// The decrypted identity file text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Debug for Ported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: a Debug print of key material has a way of
        // ending up in a log or a bug report.
        f.debug_struct("Ported")
            .field("suggested_label", &self.suggested_label)
            .field("kind", &self.kind)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

/// Open a ported identity file with the identities this machine holds.
///
/// The plaintext never reaches the filesystem.
///
/// # Errors
///
/// [`CoreError::Io`] if the file cannot be read, [`CoreError::Decrypt`] if none
/// of `identities` can open it — which is the normal outcome when the phone
/// encrypted to a different recipient than the one displayed — or
/// [`CoreError::NoIdentities`] if the plaintext holds nothing usable.
pub fn open(path: &Path, identities: &[Box<dyn age::Identity + Send + Sync>]) -> Result<Ported> {
    let bytes = std::fs::read(path).map_err(io_at(path))?;
    open_bytes(&bytes, identities)
}

/// As [`open`], for a file already in memory.
///
/// # Errors
///
/// See [`open`].
pub fn open_bytes(
    bytes: &[u8],
    identities: &[Box<dyn age::Identity + Send + Sync>],
) -> Result<Ported> {
    let plaintext = crate::decrypt::decrypt_to_memory(bytes, identities)?;
    let text = Zeroizing::new(
        String::from_utf8(plaintext.to_vec()).map_err(|_| CoreError::InvalidIdentity)?,
    );

    let (kind, recipient) = crate::store::describe_identity_text(&text)?;
    let suggested_label = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix(NAME_PREFIX))
        .map(|n| n.trim().to_owned())
        .find(|n| !n.is_empty());

    Ok(Ported {
        suggested_label,
        kind,
        recipient,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join("agepony-porting").join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// Do what the phone would do: encrypt an identity to the desktop recipient.
    fn phone_sends(label: &str, secret: &str, to: &str, out: &std::path::Path) {
        let payload = payload(label, secret);
        let plain = out.with_extension("plain");
        std::fs::write(&plain, payload.as_bytes()).expect("write payload");
        let recipients = crate::recipient::parse_all([to]).expect("parse desktop recipient");
        crate::encrypt::encrypt_file(
            &plain,
            out,
            crate::encrypt::To::Recipients(&recipients),
            false,
            &mut |_| true,
        )
        .expect("phone encrypts");
        let _ = std::fs::remove_file(&plain);
    }

    #[test]
    fn a_ported_identity_round_trips_and_carries_its_name() {
        let dir = scratch("round-trip");
        let mut desktop = Store::open(&dir).expect("open store");
        let laptop = desktop
            .generate("Laptop", Kind::PostQuantum, None)
            .expect("desktop identity");

        // The phone has its own identity and sends it to the laptop recipient.
        let phone_dir = scratch("phone");
        let mut phone = Store::open(&phone_dir).expect("open phone store");
        let phone_identity = phone
            .generate("Phone key", Kind::X25519, None)
            .expect("phone");
        let phone_secret = std::fs::read_to_string(phone.path_for(&phone_identity))
            .expect("read phone identity")
            .lines()
            .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .expect("a secret line")
            .to_owned();

        let ported_file = dir.join("ported.age");
        phone_sends("Phone key", &phone_secret, &laptop.recipient, &ported_file);

        // The laptop opens it with its own identity.
        let identities = desktop
            .load(&laptop.id, None)
            .expect("load laptop identity");
        let ported = open(&ported_file, &identities).expect("open ported file");

        assert_eq!(ported.suggested_label.as_deref(), Some("Phone key"));
        assert_eq!(ported.kind, Kind::X25519);
        assert_eq!(ported.recipient, phone_identity.recipient);
    }

    #[test]
    fn a_file_encrypted_to_someone_else_will_not_open() {
        let dir = scratch("wrong-recipient");
        let mut desktop = Store::open(&dir).expect("open");
        let mine = desktop.generate("Mine", Kind::X25519, None).expect("mine");
        let stranger = crate::identity::generate_x25519();

        let ported_file = dir.join("ported.age");
        phone_sends(
            "Someone",
            "AGE-SECRET-KEY-1QQQ",
            &stranger.to_public().to_string(),
            &ported_file,
        );

        let identities = desktop.load(&mine.id, None).expect("load");
        assert!(matches!(
            open(&ported_file, &identities),
            Err(CoreError::Decrypt(_))
        ));
    }

    #[test]
    fn a_payload_without_the_comment_lines_still_imports() {
        // The phone half must not be obliged to write our comments; a bare
        // `age -r <desktop>` over an identity string has to work.
        let dir = scratch("bare");
        let mut desktop = Store::open(&dir).expect("open");
        let laptop = desktop
            .generate("Laptop", Kind::X25519, None)
            .expect("laptop");

        let bare = crate::identity::generate_x25519();
        let secret = {
            use age::secrecy::ExposeSecret as _;
            bare.to_string().expose_secret().to_owned()
        };

        let plain = dir.join("bare.txt");
        let ported_file = dir.join("bare.age");
        std::fs::write(&plain, format!("{secret}\n")).expect("write");
        let recipients = crate::recipient::parse_all([laptop.recipient.as_str()]).expect("parse");
        crate::encrypt::encrypt_file(
            &plain,
            &ported_file,
            crate::encrypt::To::Recipients(&recipients),
            false,
            &mut |_| true,
        )
        .expect("encrypt");

        let identities = desktop.load(&laptop.id, None).expect("load");
        let ported = open(&ported_file, &identities).expect("open");
        assert_eq!(ported.suggested_label, None);
        assert_eq!(ported.recipient, bare.to_public().to_string());
    }

    #[test]
    fn opening_a_ported_file_writes_no_plaintext_anywhere() {
        // The invariant that justifies decrypt_to_memory. If this ever fails,
        // a private key is being written to disk somewhere it was not asked to
        // be, which is the worst bug this crate could have.
        let dir = scratch("no-plaintext");
        let mut desktop = Store::open(&dir).expect("open");
        let laptop = desktop
            .generate("Laptop", Kind::X25519, None)
            .expect("laptop");
        let secret = {
            use age::secrecy::ExposeSecret as _;
            crate::identity::generate_x25519()
                .to_string()
                .expose_secret()
                .to_owned()
        };

        let ported_file = dir.join("ported.age");
        phone_sends("Phone", &secret, &laptop.recipient, &ported_file);

        let before: Vec<_> = walk(&dir);
        let identities = desktop.load(&laptop.id, None).expect("load");
        let ported = open(&ported_file, &identities).expect("open");
        assert!(ported.text().contains("AGE-SECRET-KEY-"));
        let after: Vec<_> = walk(&dir);

        assert_eq!(
            before, after,
            "opening a ported file created or changed files"
        );
        for path in after {
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&secret),
                "{} contains the ported secret in the clear",
                path.display()
            );
        }
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }
}
