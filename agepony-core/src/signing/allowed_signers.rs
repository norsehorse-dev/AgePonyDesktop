//! The OpenSSH `allowed_signers` file format — AgePony's trusted-signers store
//! on the wire.
//!
//! A direct port of Android's `ssh/AllowedSigners.kt`. The two must parse and
//! serialize identically, so a list built on one platform imports losslessly on
//! the other, and either one drops straight onto a machine's
//! `ssh-keygen -Y verify -f allowed_signers`.
//!
//! Line format (ssh-keygen(1), ALLOWED SIGNERS):
//!
//! ```text
//! principals [options] keytype base64-key [comment]
//! ```
//!
//! `principals` is a comma-separated list (no spaces); `options` is an optional
//! comma-separated list of restrictions (e.g. `namespaces="agepony"`); comment
//! is free text. Blank lines and lines beginning with `#` are ignored.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// The key algorithms recognised as the start of the key field. Used to tell
/// whether the token after the principals is an options field or the key type.
/// Matches `AllowedSigners.knownKeyTypes`.
const KNOWN_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-mldsa44-ed25519@openssh.com",
];

/// One entry of an `allowed_signers` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSigner {
    /// The principals authorised to sign (e.g. `["alice@example.com"]`).
    pub principals: Vec<String>,
    /// The options field, preserved verbatim if present (e.g. `namespaces="agepony"`).
    pub options: Option<String>,
    /// The key algorithm, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Base64 of the SSH public-key wire blob.
    pub key_base64: String,
    /// An optional trailing comment.
    pub comment: Option<String>,
}

impl AllowedSigner {
    /// The public key as raw SSH wire bytes, or `None` if the base64 is invalid.
    #[must_use]
    pub fn public_key_wire(&self) -> Option<Vec<u8>> {
        BASE64.decode(self.key_base64.as_bytes()).ok()
    }
}

/// Parse an `allowed_signers` file body. Unparseable lines are skipped, exactly
/// as ssh-keygen tolerates them.
#[must_use]
pub fn parse(text: &str) -> Vec<AllowedSigner> {
    normalise(text)
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(parse_line)
        .collect()
}

/// Parse a single non-comment line, or `None` if it is not well-formed.
#[must_use]
pub fn parse_line(line: &str) -> Option<AllowedSigner> {
    let parts: Vec<&str> = line.split(' ').filter(|s| !s.is_empty()).collect();
    if parts.len() < 3 {
        return None;
    }

    let principals: Vec<String> = parts
        .first()?
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if principals.is_empty() {
        return None;
    }

    let mut index = 1;
    let mut options: Option<String> = None;

    // The token after the principals is either options or the key type.
    if !KNOWN_KEY_TYPES.contains(parts.get(index)?) {
        options = Some((*parts.get(index)?).to_owned());
        index += 1;
    }

    let key_type = (*parts.get(index)?).to_owned();
    index += 1;
    if !KNOWN_KEY_TYPES.contains(&key_type.as_str()) {
        return None;
    }

    let key_base64 = (*parts.get(index)?).to_owned();
    index += 1;
    if BASE64.decode(key_base64.as_bytes()).is_err() {
        return None;
    }

    let comment = if index < parts.len() {
        Some(parts.get(index..)?.join(" "))
    } else {
        None
    };

    Some(AllowedSigner {
        principals,
        options,
        key_type,
        key_base64,
        comment,
    })
}

/// Serialize signers back into `allowed_signers` file text (LF-terminated).
#[must_use]
pub fn serialize(signers: &[AllowedSigner]) -> String {
    let mut out = String::new();
    for s in signers {
        let mut fields = vec![s.principals.join(",")];
        if let Some(o) = s.options.as_deref().filter(|o| !o.is_empty()) {
            fields.push(o.to_owned());
        }
        fields.push(s.key_type.clone());
        fields.push(s.key_base64.clone());
        if let Some(c) = s.comment.as_deref().filter(|c| !c.is_empty()) {
            fields.push(c.to_owned());
        }
        out.push_str(&fields.join(" "));
        out.push('\n');
    }
    out
}

/// Build a signer entry from an SSH public-key line (`keytype base64 [comment]`)
/// for one or more principals. The "promote a recipient to a signer" path.
///
/// `namespace_restricted` adds `namespaces="agepony"` so the entry only
/// authorises AgePony-namespaced signatures.
#[must_use]
pub fn make_signer(
    principals: &[String],
    ssh_public_key_line: &str,
    namespace_restricted: bool,
) -> Option<AllowedSigner> {
    let parts: Vec<&str> = ssh_public_key_line
        .trim()
        .split(' ')
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() < 2 {
        return None;
    }
    let key_type = (*parts.first()?).to_owned();
    if !KNOWN_KEY_TYPES.contains(&key_type.as_str()) {
        return None;
    }
    let key_base64 = (*parts.get(1)?).to_owned();
    if BASE64.decode(key_base64.as_bytes()).is_err() {
        return None;
    }
    let comment = if parts.len() >= 3 {
        Some(parts.get(2..)?.join(" "))
    } else {
        None
    };
    let options = if namespace_restricted {
        Some(format!("namespaces=\"{}\"", super::NAMESPACE))
    } else {
        None
    };
    Some(AllowedSigner {
        principals: principals.to_vec(),
        options,
        key_type,
        key_base64,
        comment,
    })
}

fn normalise(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real ssh-keygen allowed_signers line for the ed25519 fixture key.
    const ED_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPufhC9ET6WoSU5oEErYNpBN4bTw2ZUA4wiyIYIOPlU kevin@agepony";

    #[test]
    fn a_plain_line_parses() {
        let line = format!("kevin@agepony {ED_PUB}");
        let s = parse_line(&line).expect("parses");
        assert_eq!(s.principals, vec!["kevin@agepony"]);
        assert_eq!(s.key_type, "ssh-ed25519");
        assert!(s.options.is_none());
        assert_eq!(s.comment.as_deref(), Some("kevin@agepony"));
        assert!(s.public_key_wire().is_some());
    }

    #[test]
    fn an_options_field_is_detected_and_preserved() {
        let line = format!("alice@example.com namespaces=\"agepony\" {ED_PUB}");
        let s = parse_line(&line).expect("parses");
        assert_eq!(s.options.as_deref(), Some("namespaces=\"agepony\""));
        assert_eq!(s.key_type, "ssh-ed25519");
    }

    #[test]
    fn several_principals_split_on_commas() {
        let line = format!("alice,bob {ED_PUB}");
        let s = parse_line(&line).expect("parses");
        assert_eq!(s.principals, vec!["alice", "bob"]);
    }

    #[test]
    fn parse_serialize_round_trips() {
        let body =
            format!("# a comment\nkevin@agepony {ED_PUB}\nalice namespaces=\"agepony\" {ED_PUB}\n");
        let parsed = parse(&body);
        assert_eq!(parsed.len(), 2);
        let round = parse(&serialize(&parsed));
        assert_eq!(parsed, round, "parse ∘ serialize must be stable");
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let body = format!("\n  \n# nope\nkevin@agepony {ED_PUB}\n");
        assert_eq!(parse(&body).len(), 1);
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        assert!(parse_line("only-principals").is_none());
        assert!(parse_line("kevin ssh-ed25519").is_none()); // no key
        assert!(parse_line("kevin not-a-keytype AAAA").is_none());
        assert!(parse_line("kevin ssh-ed25519 !!!not-base64!!!").is_none());
    }

    #[test]
    fn make_signer_from_a_public_key_line() {
        let s = make_signer(&["team@agepony".to_owned()], ED_PUB, true).expect("makes");
        assert_eq!(s.principals, vec!["team@agepony"]);
        assert_eq!(s.options.as_deref(), Some("namespaces=\"agepony\""));
        assert_eq!(s.key_type, "ssh-ed25519");
    }
}
