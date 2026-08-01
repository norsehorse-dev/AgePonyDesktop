//! Identity generation, parsing and on-disk storage.

use crate::error::{CoreError, Result, io_at};
use age::secrecy::SecretString;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// Generate a fresh classical X25519 identity.
#[must_use]
pub fn generate_x25519() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

/// Generate a fresh post-quantum `mlkem768x25519` identity.
///
/// # Errors
///
/// [`CoreError::BareIo`] if the OS randomness source fails.
pub fn generate_pq() -> Result<crate::pq::Identity> {
    crate::pq::Identity::generate()
}

/// Render an identity file body: the age-conventional two comment lines
/// followed by the secret key.
#[must_use]
pub fn identity_file_body(public: &str, secret: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(format!(
        "# created by AgePony Desktop\n# public key: {public}\n{secret}\n"
    ))
}

/// Load every identity in an age identity file.
///
/// Handles plain identity files. Passphrase-encrypted identity files are
/// Phase 3.
///
/// # Errors
///
/// [`CoreError::Io`] if the file cannot be read, [`CoreError::NoIdentities`]
/// if it parses but contains nothing usable.
pub fn load_file(path: &Path) -> Result<Vec<Box<dyn age::Identity + Send + Sync>>> {
    let text = fs::read_to_string(path).map_err(io_at(path))?;
    parse_identities(&text)
}

/// Parse identities out of the text of an identity file.
///
/// # Errors
///
/// [`CoreError::NoIdentities`] if nothing usable was found.
pub fn parse_identities(text: &str) -> Result<Vec<Box<dyn age::Identity + Send + Sync>>> {
    let mut out: Vec<Box<dyn age::Identity + Send + Sync>> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Check the post-quantum prefix first. An `AGE-SECRET-KEY-PQ-1…`
        // string also begins with `AGE-SECRET-KEY-`, so testing the classical
        // form first would misparse it -- or, worse, silently skip it and
        // surface later as "wrong identity", which is a miserable thing to
        // debug. A malformed PQ line is a hard error, not a skip.
        if line.to_uppercase().starts_with(crate::pq::IDENTITY_HRP) {
            out.push(Box::new(crate::pq::Identity::from_bech32(line)?));
            continue;
        }
        if let Ok(id) = line.parse::<age::x25519::Identity>() {
            out.push(Box::new(id));
        }
    }

    if out.is_empty() {
        return Err(CoreError::NoIdentities);
    }
    Ok(out)
}

/// Whether `text` looks like an age-encrypted identity file rather than a
/// plain one.
///
/// A passphrase-protected identity is just an age file whose plaintext is an
/// ordinary identity file, so the check is the age header — binary or armored.
/// This is the same format `age-keygen | age -p` produces, which is the point:
/// the file stays readable by the reference tooling.
#[must_use]
pub fn looks_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(b"age-encryption.org/")
        || bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
}

/// Load identities from a file, decrypting it first if it is passphrase
/// protected.
///
/// `passphrase` is consulted only if the file turns out to be encrypted.
///
/// # Errors
///
/// [`CoreError::PassphraseRequired`] if the file is encrypted and no passphrase
/// was supplied, [`CoreError::Decrypt`] if the passphrase is wrong, or
/// [`CoreError::NoIdentities`] if the plaintext holds nothing usable.
pub fn load_file_maybe_encrypted(
    path: &Path,
    passphrase: Option<&SecretString>,
) -> Result<Vec<Box<dyn age::Identity + Send + Sync>>> {
    let bytes = fs::read(path).map_err(io_at(path))?;

    if !looks_encrypted(&bytes) {
        let text = String::from_utf8(bytes).map_err(|_| CoreError::InvalidIdentity)?;
        return parse_identities(&text);
    }

    let passphrase = passphrase.ok_or(CoreError::PassphraseRequired)?;
    let plaintext = decrypt_identity_bytes(&bytes, passphrase)?;
    let text = std::str::from_utf8(&plaintext).map_err(|_| CoreError::InvalidIdentity)?;
    parse_identities(text)
}

/// Decrypt a passphrase-protected identity file held in memory.
///
/// Identity files are a few kilobytes at most, so unlike real payloads these
/// are handled in memory — but in a [`Zeroizing`] buffer, and the plaintext
/// never reaches disk.
fn decrypt_identity_bytes(bytes: &[u8], passphrase: &SecretString) -> Result<Zeroizing<Vec<u8>>> {
    let armored = age::armor::ArmoredReader::new(bytes);
    let decryptor = age::Decryptor::new(armored)?;
    let identity = age::scrypt::Identity::new(passphrase.clone());
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;

    let mut out = Zeroizing::new(Vec::new());
    std::io::Read::read_to_end(&mut reader, &mut out)?;
    Ok(out)
}

/// Write an identity file, encrypted to a passphrase.
///
/// Uses age's own passphrase encryption, so the result is an ordinary age file
/// that `age -d` and the mobile apps can open.
///
/// # Errors
///
/// [`CoreError::Io`] on a filesystem failure, [`CoreError::Encrypt`] if age
/// refuses the passphrase.
pub fn save_encrypted_identity_file(
    path: &Path,
    contents: &str,
    passphrase: &SecretString,
) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(io_at(dir))?;

    let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
    let mut buffer = Vec::new();
    {
        let mut writer = encryptor.wrap_output(&mut buffer)?;
        std::io::Write::write_all(&mut writer, contents.as_bytes())?;
        writer.finish()?;
    }

    let tmp = crate::encrypt::sibling_temp(path);
    fs::write(&tmp, &buffer).map_err(io_at(&tmp))?;
    set_owner_only(&tmp)?;
    fs::rename(&tmp, path).map_err(io_at(path))?;
    Ok(())
}

/// Write an identity file with `0600` permissions on Unix.
///
/// Writes to a sibling dotfile and renames, so a crash mid-write cannot leave a
/// half-written key at the real path.
///
/// # Errors
///
/// [`CoreError::Io`] on any filesystem failure.
pub fn save_identity_file(path: &Path, contents: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(io_at(dir))?;

    let tmp = crate::encrypt::sibling_temp(path);
    fs::write(&tmp, contents).map_err(io_at(&tmp))?;
    set_owner_only(&tmp)?;
    fs::rename(&tmp, path).map_err(io_at(path))?;
    Ok(())
}

/// Restrict a file to the owner. No-op on non-Unix.
///
/// # Errors
///
/// [`CoreError::Io`] if the mode cannot be set.
pub fn set_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_at(path))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret as _;

    #[test]
    fn generated_identity_round_trips_through_its_string_form() {
        let id = generate_x25519();
        let s = id.to_string();
        let parsed = parse_identities(s.expose_secret()).expect("parses");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let id = generate_x25519();
        let text = format!(
            "# created: whenever\n# public key: {}\n\n{}\n",
            id.to_public(),
            id.to_string().expose_secret()
        );
        assert_eq!(parse_identities(&text).expect("parses").len(), 1);
    }

    #[test]
    fn an_empty_file_is_an_error_not_an_empty_vec() {
        assert!(matches!(
            parse_identities("# nothing here\n"),
            Err(CoreError::NoIdentities)
        ));
    }

    #[test]
    fn a_malformed_pq_identity_fails_loudly_rather_than_being_skipped() {
        let text = format!("{}1qqqqqqqqqq\n", crate::pq::IDENTITY_HRP);
        assert!(matches!(
            parse_identities(&text),
            Err(CoreError::InvalidIdentity)
        ));
    }

    #[test]
    fn an_encrypted_identity_file_round_trips() {
        let id = generate_x25519();
        let body = identity_file_body(&id.to_public().to_string(), id.to_string().expose_secret());
        let passphrase = SecretString::from("correct horse battery staple");

        let dir = std::env::temp_dir().join("agepony-encrypted-identity");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("id.age");

        save_encrypted_identity_file(&path, &body, &passphrase).expect("save");

        let raw = fs::read(&path).expect("read");
        assert!(
            looks_encrypted(&raw),
            "the file on disk must be an age file"
        );
        assert!(
            !String::from_utf8_lossy(&raw).contains("AGE-SECRET-KEY-"),
            "the secret must not be visible in the encrypted file"
        );

        let loaded =
            load_file_maybe_encrypted(&path, Some(&passphrase)).expect("load with passphrase");
        assert_eq!(loaded.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_encrypted_identity_without_a_passphrase_says_so() {
        let id = generate_x25519();
        let body = identity_file_body(&id.to_public().to_string(), id.to_string().expose_secret());
        let dir = std::env::temp_dir().join("agepony-encrypted-identity-2");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("id.age");
        save_encrypted_identity_file(&path, &body, &SecretString::from("hunter2")).expect("save");

        assert!(matches!(
            load_file_maybe_encrypted(&path, None),
            Err(CoreError::PassphraseRequired)
        ));
        assert!(matches!(
            load_file_maybe_encrypted(&path, Some(&SecretString::from("wrong"))),
            Err(CoreError::Decrypt(_))
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plain_identity_file_loads_without_a_passphrase() {
        let id = generate_x25519();
        let body = identity_file_body(&id.to_public().to_string(), id.to_string().expose_secret());
        let dir = std::env::temp_dir().join("agepony-plain-identity");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("id.txt");
        save_identity_file(&path, &body).expect("save");

        assert_eq!(
            load_file_maybe_encrypted(&path, None).expect("load").len(),
            1
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pq_identity_file_parses() {
        let id = generate_pq().expect("generate");
        let text = id.to_bech32().expect("encode");
        let parsed = parse_identities(&text).expect("parses");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn a_mixed_identity_file_yields_both() {
        let classical = generate_x25519();
        let pq = generate_pq().expect("generate");
        let text = format!(
            "# a file with both kinds\n{}\n{}\n",
            classical.to_string().expose_secret(),
            pq.to_bech32().expect("encode").as_str()
        );
        assert_eq!(parse_identities(&text).expect("parses").len(), 2);
    }
}
