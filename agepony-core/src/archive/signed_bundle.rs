//! The AgePony "signed bundle": a small USTAR archive carrying a payload
//! together with a detached SSHSIG over it, so an encrypt-and-sign produces a
//! single `.age` file. The whole bundle is age-encrypted (sign-then-encrypt),
//! which keeps the signer's identity hidden inside the ciphertext.
//!
//! A direct port of Android's `archive/SignedBundle.kt`. Entry order:
//!
//! ```text
//! .agepony-signed  — marker + manifest ("agepony-signed/1\nname=<original>\n")
//! payload          — the original file bytes (what was signed)
//! payload.sig      — the armored SSHSIG over `payload`
//! ```
//!
//! [`parse`] returns `None` for anything that is not a signed bundle — plain
//! files (not a tar) and ordinary multi-file bundles (a tar whose first entry is
//! not the marker) — so the decrypt path can safely probe every decrypted output.

use super::tar::{self, Entry};
use crate::error::Result;

const MARKER: &str = ".agepony-signed";
const PAYLOAD: &str = "payload";
const SIGNATURE: &str = "payload.sig";
const VERSION_LINE: &str = "agepony-signed/1";

/// A parsed signed bundle.
#[derive(Debug, Clone)]
pub struct Parsed {
    /// The original file name recorded in the manifest.
    pub name: String,
    /// The payload bytes (what was signed).
    pub payload: Vec<u8>,
    /// The armored SSHSIG over the payload.
    pub signature_armored: String,
}

/// Build the bundle tar from a payload and its armored SSHSIG.
///
/// # Errors
///
/// Whatever [`tar::create`] returns for an oversized entry or name.
pub fn build(original_name: &str, payload: &[u8], signature_armored: &str) -> Result<Vec<u8>> {
    let manifest = format!("{VERSION_LINE}\nname={}\n", sanitize_name(original_name));
    tar::create(&[
        Entry {
            name: MARKER.to_owned(),
            data: manifest.into_bytes(),
        },
        Entry {
            name: PAYLOAD.to_owned(),
            data: payload.to_vec(),
        },
        Entry {
            name: SIGNATURE.to_owned(),
            data: signature_armored.as_bytes().to_vec(),
        },
    ])
}

/// Parse `bytes` as a signed bundle, or return `None` if it is not one.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<Parsed> {
    let entries = tar::extract(bytes).ok()?; // not a valid tar -> not a bundle
    let first = entries.first()?;
    if first.name != MARKER {
        return None;
    }
    let manifest = String::from_utf8_lossy(&first.data);
    if !manifest.starts_with("agepony-signed/") {
        return None;
    }
    let payload = entries.iter().find(|e| e.name == PAYLOAD)?;
    let sig = entries.iter().find(|e| e.name == SIGNATURE)?;
    let name = manifest
        .lines()
        .find_map(|l| l.strip_prefix("name="))
        .map(str::to_owned)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "file".to_owned());
    Some(Parsed {
        name,
        payload: payload.data.clone(),
        signature_armored: String::from_utf8_lossy(&sig.data).into_owned(),
    })
}

fn sanitize_name(name: &str) -> String {
    let cleaned = name.replace(['\n', '\r'], "_");
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "file".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_round_trips() {
        let bundle = build(
            "report.pdf",
            b"the payload",
            "-----BEGIN SSH SIGNATURE-----\n…\n",
        )
        .unwrap();
        let parsed = parse(&bundle).expect("is a bundle");
        assert_eq!(parsed.name, "report.pdf");
        assert_eq!(parsed.payload, b"the payload");
        assert!(parsed.signature_armored.contains("BEGIN SSH SIGNATURE"));
    }

    #[test]
    fn the_marker_is_the_first_entry() {
        let bundle = build("x", b"y", "sig").unwrap();
        let entries = tar::extract(&bundle).unwrap();
        assert_eq!(entries[0].name, ".agepony-signed");
        assert_eq!(entries[1].name, "payload");
        assert_eq!(entries[2].name, "payload.sig");
    }

    #[test]
    fn a_plain_file_is_not_a_bundle() {
        assert!(parse(b"just some bytes, definitely not a tar").is_none());
    }

    #[test]
    fn an_ordinary_tar_is_not_a_bundle() {
        let tar = tar::create(&[Entry {
            name: "a.txt".to_owned(),
            data: b"hi".to_vec(),
        }])
        .unwrap();
        assert!(parse(&tar).is_none(), "first entry is not the marker");
    }

    #[test]
    fn a_name_with_newlines_is_sanitised() {
        let bundle = build("evil\nname", b"p", "s").unwrap();
        assert_eq!(parse(&bundle).unwrap().name, "evil_name");
    }

    #[test]
    fn a_blank_name_falls_back_to_file() {
        let bundle = build("   ", b"p", "s").unwrap();
        assert_eq!(parse(&bundle).unwrap().name, "file");
    }
}
