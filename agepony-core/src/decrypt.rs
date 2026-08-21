//! Streaming decryption.
//!
//! Same partial-output discipline as [`crate::encrypt`]: a failed decrypt must
//! not leave a truncated, unauthenticated plaintext on disk.

use crate::encrypt::TempOut;
use crate::error::{CoreError, Result, io_at};
use crate::{CHUNK, ProgressFn};
use age::armor::ArmoredReader;
use age::secrecy::SecretString;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

/// How to decrypt.
pub enum With<'a> {
    /// With one or more loaded identities.
    Identities(&'a [Box<dyn age::Identity + Send + Sync>]),
    /// With a passphrase (scrypt).
    Passphrase(SecretString),
}

/// Whether the file at `path` starts like an age file, binary or armored.
///
/// This is the routing question the Files screen asks about every drop, and it
/// is answered by reading the first bytes rather than by trusting the name. An
/// extension is a claim; the header is a fact. A real age file someone renamed
/// to `report.bak` still opens, and a text file someone called `notes.age` gets
/// sealed rather than fed to the decryptor to fail with a parse error.
///
/// Reads at most 64 bytes. A file that cannot be opened or read answers
/// `false`, which routes it to the seal group — where the encryptor will
/// produce a real error message about the unreadable file, instead of this
/// function inventing one of its own.
#[must_use]
pub fn looks_like_age_file(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut head = [0_u8; 64];
    let mut filled = 0;
    // Loop rather than one read: a single read may legally return short.
    while let Some(rest) = head.get_mut(filled..).filter(|r| !r.is_empty()) {
        match file.read(rest) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return false,
        }
    }
    crate::identity::looks_encrypted(head.get(..filled).unwrap_or_default())
}

/// Decrypt `input` to `output`.
///
/// Accepts both binary and ASCII-armored input; the armor reader detects which.
///
/// # Errors
///
/// [`CoreError::Decrypt`] for a wrong identity or a failed authentication tag,
/// [`CoreError::Io`] for filesystem trouble. In every error case the output
/// file is removed.
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    with: With<'_>,
    on_progress: ProgressFn<'_>,
) -> Result<()> {
    let total = fs::metadata(input).map_err(io_at(input))?.len();
    let source = File::open(input).map_err(io_at(input))?;
    let armored = ArmoredReader::new(BufReader::with_capacity(CHUNK, source));
    let decryptor = age::Decryptor::new(armored)?;

    let passphrase_identity;
    let mut reader = match with {
        With::Identities(ids) => {
            if ids.is_empty() {
                return Err(CoreError::NoIdentities);
            }
            decryptor.decrypt(ids.iter().map(|i| i.as_ref() as &dyn age::Identity))?
        }
        With::Passphrase(p) => {
            passphrase_identity = crate::passphrase::identity(p);
            decryptor.decrypt(std::iter::once(&passphrase_identity as &dyn age::Identity))?
        }
    };

    let (guard, mut sink) = TempOut::create(output)?;

    // Zeroizing so a panic or an early return does not leave a chunk of
    // plaintext sitting in freed heap memory.
    let mut buf = zeroize::Zeroizing::new(vec![0_u8; CHUNK]);
    let mut done: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sink.write_all(buf.get(..n).ok_or_else(|| {
            CoreError::BareIo(std::io::Error::other("short read exceeded buffer"))
        })?)?;
        done = done.saturating_add(n as u64);
        // Denominator is the ciphertext length, so this reads slightly
        // pessimistic. Good enough for a progress bar, and it never exceeds 1.
        let frac = if total == 0 {
            1.0
        } else {
            (done as f32 / total as f32).clamp(0.0, 1.0)
        };
        if !on_progress(frac) {
            return Err(CoreError::Cancelled);
        }
    }

    sink.flush()?;
    sink.sync_all().map_err(io_at(output))?;
    guard.commit()
}

/// Decrypt a small age file held in memory, returning the plaintext in a
/// [`Zeroizing`] buffer.
///
/// For key material only — identity files and ported identities, which are a
/// few kilobytes. Real payloads stream to disk via [`decrypt_file`]; this
/// exists precisely so ported key material never touches the filesystem.
///
/// # Errors
///
/// [`CoreError::Decrypt`] if no identity matches or authentication fails.
pub fn decrypt_to_memory(
    bytes: &[u8],
    identities: &[Box<dyn age::Identity + Send + Sync>],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if identities.is_empty() {
        return Err(CoreError::NoIdentities);
    }
    let armored = ArmoredReader::new(bytes);
    let decryptor = age::Decryptor::new(armored)?;
    let mut reader =
        decryptor.decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))?;

    let mut out = zeroize::Zeroizing::new(Vec::new());
    Read::read_to_end(&mut reader, &mut out)?;
    Ok(out)
}

/// Decrypt `ciphertext` held in memory to a [`Zeroizing`] plaintext buffer,
/// with identities or a passphrase.
///
/// This is the Text screen's counterpart to [`decrypt_file`]. Unlike
/// [`decrypt_to_memory`], which is identity-only and exists for key material, a
/// pasted note may just as well be passphrase-encrypted, so this takes the full
/// [`With`]. The result is [`Zeroizing`] because this is the one path where
/// plaintext returns to the UI rather than going straight to a file; the caller
/// must not copy it into a buffer that outlives use.
///
/// Accepts both binary and ASCII-armored input.
///
/// # Errors
///
/// [`CoreError::NoIdentities`] for an empty identity set, or
/// [`CoreError::Decrypt`] for a wrong identity/passphrase or a failed tag.
pub fn decrypt_bytes(ciphertext: &[u8], with: With<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let armored = ArmoredReader::new(ciphertext);
    let decryptor = age::Decryptor::new(armored)?;

    let passphrase_identity;
    let mut reader = match with {
        With::Identities(ids) => {
            if ids.is_empty() {
                return Err(CoreError::NoIdentities);
            }
            decryptor.decrypt(ids.iter().map(|i| i.as_ref() as &dyn age::Identity))?
        }
        With::Passphrase(p) => {
            passphrase_identity = crate::passphrase::identity(p);
            decryptor.decrypt(std::iter::once(&passphrase_identity as &dyn age::Identity))?
        }
    };

    let mut out = zeroize::Zeroizing::new(Vec::new());
    Read::read_to_end(&mut reader, &mut out)?;
    Ok(out)
}

/// The conventional output path for decrypting `input`: strip a trailing
/// `.age`, or append `.decrypted` if there is nothing to strip.
#[must_use]
pub fn default_output_path(input: &Path) -> std::path::PathBuf {
    if input
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("age"))
    {
        input.with_extension("")
    } else {
        let mut s = input.as_os_str().to_os_string();
        s.push(".decrypted");
        s.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_believes_headers_and_not_names() {
        let dir = std::env::temp_dir().join("agepony-probe-test");
        let _ = fs::create_dir_all(&dir);

        // A real binary age file wearing the wrong name entirely.
        let renamed = dir.join("report.bak");
        fs::write(
            &renamed,
            include_bytes!("../tests/fixtures/x25519_hello.age"),
        )
        .expect("write fixture");
        assert!(
            looks_like_age_file(&renamed),
            "a renamed age file must probe true"
        );

        // An armored age file. The armor header is text, so this also proves
        // the probe is not just matching the binary magic.
        let armored = dir.join("armored.age");
        fs::write(
            &armored,
            b"-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3Yx\n",
        )
        .expect("write armored");
        assert!(looks_like_age_file(&armored), "armored must probe true");

        // The lie in the other direction: a text file named like an age file.
        let impostor = dir.join("notes.age");
        fs::write(&impostor, b"shopping: oats, apples, horseshoes\n").expect("write impostor");
        assert!(
            !looks_like_age_file(&impostor),
            "a text file named .age must probe false"
        );

        // Shorter than the probe's buffer, and empty entirely.
        let tiny = dir.join("tiny.age");
        fs::write(&tiny, b"age").expect("write tiny");
        assert!(!looks_like_age_file(&tiny));
        let empty = dir.join("empty.age");
        fs::write(&empty, b"").expect("write empty");
        assert!(!looks_like_age_file(&empty));

        // Missing files answer false rather than erroring: the seal path will
        // produce the real complaint about an unreadable file.
        assert!(!looks_like_age_file(&dir.join("no-such-file")));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn text_round_trips_through_recipients() {
        let id = age::x25519::Identity::generate();
        let parsed = crate::recipient::parse(&id.to_public().to_string()).expect("recipient");
        let ct = crate::encrypt::encrypt_bytes(
            b"shopping: oats, apples, horseshoes",
            crate::encrypt::To::Recipients(std::slice::from_ref(&parsed)),
            true,
        )
        .expect("encrypt");
        // Armored output is meant to be copied, so it must be ASCII text.
        assert!(ct.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];
        let pt = decrypt_bytes(&ct, With::Identities(&ids)).expect("decrypt");
        assert_eq!(&pt[..], b"shopping: oats, apples, horseshoes");
    }

    #[test]
    fn text_round_trips_through_passphrase() {
        let ct = crate::encrypt::encrypt_bytes(
            b"correct horse",
            crate::encrypt::To::Passphrase(SecretString::from("battery staple".to_owned())),
            true,
        )
        .expect("encrypt");
        let pt = decrypt_bytes(
            &ct,
            With::Passphrase(SecretString::from("battery staple".to_owned())),
        )
        .expect("decrypt");
        assert_eq!(&pt[..], b"correct horse");

        assert!(
            decrypt_bytes(
                &ct,
                With::Passphrase(SecretString::from("wrong".to_owned()))
            )
            .is_err(),
            "a wrong passphrase must be refused"
        );
    }

    #[test]
    fn text_and_file_modes_are_the_same_format() {
        // Text encrypted in memory must open with the file decryptor, and a
        // file encrypted to disk must open with the in-memory decryptor:
        // proof the two paths are one format, not two.
        let id = age::x25519::Identity::generate();
        let parsed = crate::recipient::parse(&id.to_public().to_string()).expect("recipient");
        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];

        let dir = std::env::temp_dir().join("agepony-text-file-parity");
        let _ = fs::create_dir_all(&dir);

        // in-memory encrypt -> file decrypt
        let ct = crate::encrypt::encrypt_bytes(
            b"one format",
            crate::encrypt::To::Recipients(std::slice::from_ref(&parsed)),
            false,
        )
        .expect("encrypt bytes");
        let ct_path = dir.join("mem.age");
        fs::write(&ct_path, &ct).expect("write ct");
        let out_path = dir.join("mem.out");
        decrypt_file(&ct_path, &out_path, With::Identities(&ids), &mut |_| true)
            .expect("file decrypt of in-memory ciphertext");
        assert_eq!(fs::read(&out_path).expect("read out"), b"one format");

        // file encrypt -> in-memory decrypt
        let plain_path = dir.join("plain.txt");
        fs::write(&plain_path, b"other way").expect("write plain");
        let file_ct = dir.join("plain.txt.age");
        crate::encrypt::encrypt_file(
            &plain_path,
            &file_ct,
            crate::encrypt::To::Recipients(std::slice::from_ref(&parsed)),
            false,
            &mut |_| true,
        )
        .expect("file encrypt");
        let pt = decrypt_bytes(
            &fs::read(&file_ct).expect("read ct"),
            With::Identities(&ids),
        )
        .expect("in-memory decrypt of file ciphertext");
        assert_eq!(&pt[..], b"other way");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dot_age_is_stripped() {
        assert_eq!(
            default_output_path(Path::new("/a/report.pdf.age")),
            Path::new("/a/report.pdf")
        );
    }

    #[test]
    fn armored_txt_gets_a_suffix_rather_than_losing_its_extension() {
        assert_eq!(
            default_output_path(Path::new("/a/note.txt")),
            Path::new("/a/note.txt.decrypted")
        );
    }
}
