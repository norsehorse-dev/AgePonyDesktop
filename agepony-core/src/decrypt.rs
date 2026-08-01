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
            passphrase_identity = age::scrypt::Identity::new(p);
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
