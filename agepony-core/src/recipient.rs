//! Parsing age recipient strings.
//!
//! Classical `age1…` and SSH recipients are handled by the `age` crate.
//! Post-quantum `age1pq1…` recipients are AgePony's own implementation; see
//! [`crate::pq`].

use crate::error::{CoreError, Result};

/// Which flavour of recipient a string turned out to be.
///
/// This matters at the encrypt layer: age refuses to mix stanza label sets, so
/// a post-quantum recipient cannot share a file with a classical one. We check
/// this ourselves so the error is legible rather than an
/// `IncompatibleRecipients` from deep inside the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `age1…` — X25519. Not quantum-safe.
    X25519,
    /// `age1pq1…` — MLKEM768-X25519 hybrid. Quantum-safe.
    PostQuantum,
    /// `ssh-ed25519 …` or `ssh-rsa …`. Not quantum-safe.
    Ssh,
}

impl Kind {
    /// Whether a file encrypted only to recipients of this kind is quantum-safe.
    #[must_use]
    pub fn is_post_quantum(self) -> bool {
        matches!(self, Kind::PostQuantum)
    }
}

/// A parsed recipient, ready to hand to the encryptor.
pub struct Parsed {
    /// The recipient itself.
    pub recipient: Box<dyn age::Recipient + Send>,
    /// What kind it is.
    pub kind: Kind,
    /// The canonical string form, as typed.
    pub encoded: String,
}

impl std::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field("kind", &self.kind)
            .field("encoded", &self.encoded)
            .finish_non_exhaustive()
    }
}

/// Parse a single recipient string.
///
/// # Errors
///
/// Returns [`CoreError::InvalidRecipient`] if the string is not a recipient
/// this build understands. Note that `age1pq1…` currently lands in
/// [`CoreError::NotImplemented`] until Phase 4 lands [`crate::pq`].
pub fn parse(s: &str) -> Result<Parsed> {
    let s = s.trim();

    // Bech32 is case-insensitive, and an all-uppercase recipient is not a
    // curiosity: uppercasing is what lets a post-quantum recipient reach QR
    // alphanumeric mode, which is two whole QR versions smaller than byte
    // mode. So the prefix tests below have to be case-insensitive, or the
    // string we put in our own QR code would not parse when scanned back.
    let lower = s.to_lowercase();

    if lower.starts_with(crate::pq::RECIPIENT_HRP_PREFIX) {
        let recipient = crate::pq::Recipient::from_bech32(s)?;
        return Ok(Parsed {
            recipient: Box::new(recipient),
            kind: Kind::PostQuantum,
            encoded: s.to_owned(),
        });
    }

    if lower.starts_with("age1") {
        let r: age::x25519::Recipient = s
            .parse()
            .map_err(|_| CoreError::InvalidRecipient(s.to_owned()))?;
        return Ok(Parsed {
            recipient: Box::new(r),
            kind: Kind::X25519,
            encoded: s.to_owned(),
        });
    }

    // SSH recipients are not bech32 and are genuinely case-sensitive.
    if s.starts_with("ssh-") {
        let r: age::ssh::Recipient = s
            .parse()
            .map_err(|_| CoreError::InvalidRecipient(s.to_owned()))?;
        return Ok(Parsed {
            recipient: Box::new(r),
            kind: Kind::Ssh,
            encoded: s.to_owned(),
        });
    }

    Err(CoreError::InvalidRecipient(s.to_owned()))
}

/// Parse many recipients and reject a classical/post-quantum mix up front.
///
/// # Errors
///
/// [`CoreError::NoRecipients`] for an empty list, [`CoreError::MixedPostQuantum`]
/// for a mix, or whatever [`parse`] returns for a bad string.
pub fn parse_all<I, S>(strings: I) -> Result<Vec<Parsed>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let parsed: Vec<Parsed> = strings
        .into_iter()
        .map(|s| parse(s.as_ref()))
        .collect::<Result<_>>()?;

    if parsed.is_empty() {
        return Err(CoreError::NoRecipients);
    }

    let pq = parsed.iter().filter(|p| p.kind.is_post_quantum()).count();
    if pq != 0 && pq != parsed.len() {
        return Err(CoreError::MixedPostQuantum);
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_recipient_parses() {
        let id = age::x25519::Identity::generate();
        let p = parse(&id.to_public().to_string()).expect("valid recipient");
        assert_eq!(p.kind, Kind::X25519);
    }

    #[test]
    fn an_uppercase_recipient_parses_to_the_same_key() {
        // What a QR code round trip does.
        let id = age::x25519::Identity::generate();
        let encoded = id.to_public().to_string();
        let lower = parse(&encoded).expect("lowercase");
        let upper = parse(&encoded.to_uppercase()).expect("uppercase");
        assert_eq!(lower.kind, upper.kind);
        assert_eq!(lower.kind, Kind::X25519);
    }

    #[test]
    fn an_uppercase_post_quantum_recipient_parses() {
        let recipient = crate::pq::Identity::generate()
            .expect("generate")
            .to_public()
            .expect("public")
            .to_string();
        let parsed = parse(&recipient.to_uppercase()).expect("uppercase pq recipient");
        assert_eq!(parsed.kind, Kind::PostQuantum);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            parse("definitely not a recipient"),
            Err(CoreError::InvalidRecipient(_))
        ));
    }

    #[test]
    fn empty_recipient_list_is_rejected() {
        let empty: Vec<String> = vec![];
        assert!(matches!(parse_all(empty), Err(CoreError::NoRecipients)));
    }
}
