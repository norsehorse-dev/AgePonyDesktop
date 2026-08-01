//! Streaming encryption.
//!
//! Everything writes to a sibling dotfile in the destination directory and
//! renames on success. Never `/tmp`: a temp file on another filesystem means
//! the rename becomes a copy, which means plaintext lands somewhere the user
//! did not choose.

use crate::error::{CoreError, Result, io_at};
use crate::{CHUNK, ProgressFn};
use age::armor::{ArmoredWriter, Format};
use age::secrecy::SecretString;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

/// How to encrypt.
pub enum To<'a> {
    /// To one or more parsed recipients.
    Recipients(&'a [crate::recipient::Parsed]),
    /// To a passphrase (scrypt). Mutually exclusive with recipients; age
    /// enforces that, and so does this enum.
    Passphrase(SecretString),
}

/// A destination file that deletes itself unless committed.
///
/// This is the whole partial-output story: if encryption fails, or the process
/// unwinds, `Drop` removes the incomplete file. Only [`TempOut::commit`]
/// renames it into place.
pub(crate) struct TempOut {
    tmp: PathBuf,
    final_path: PathBuf,
    committed: bool,
}

impl TempOut {
    pub(crate) fn create(final_path: &Path) -> Result<(Self, File)> {
        if let Some(dir) = final_path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir).map_err(io_at(dir))?;
            }
        }
        let tmp = sibling_temp(final_path);
        let file = File::create(&tmp).map_err(io_at(&tmp))?;
        Ok((
            Self {
                tmp,
                final_path: final_path.to_path_buf(),
                committed: false,
            },
            file,
        ))
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        fs::rename(&self.tmp, &self.final_path).map_err(io_at(&self.final_path))?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for TempOut {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort. If this fails there is nothing useful to do, and
            // panicking in Drop is worse than a stray dotfile.
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// The dotfile path used for in-progress output, alongside `path`.
pub(crate) fn sibling_temp(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map_or_else(|| String::from("out"), |n| n.to_string_lossy().into_owned());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{name}.agepony-partial"))
}

/// A path that does not exist yet, derived from `path`.
///
/// Returns `path` itself if it is free, otherwise inserts ` (2)`, ` (3)` … before
/// the extension.
///
/// This matters more than it looks. Encrypting `notes.txt` writes
/// `notes.txt.age`; do it twice and the second run would silently destroy the
/// first. Worse, decrypting `notes.txt.age` defaults to `notes.txt` — straight
/// over the original plaintext if it is still sitting there. Batch operations
/// turn both from "unlikely" into "eventually".
#[must_use]
pub fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    // Split on the FIRST dot rather than using `extension()`, so `a.tar.gz`
    // becomes `a (2).tar.gz` rather than `a.tar (2).gz`.
    let (stem, ext) = match name.find('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name.as_ref(), ""),
    };

    for n in 2..10_000 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    // Pathological: ten thousand collisions. Overwriting is still wrong, so
    // hand back something that will fail loudly rather than silently clobber.
    dir.join(format!("{stem} (full){ext}"))
}

/// Encrypt `input` to `output`.
///
/// `on_progress` is called with a fraction in `0.0..=1.0`; returning `false`
/// aborts and leaves no output file.
///
/// # Errors
///
/// [`CoreError::NoRecipients`], [`CoreError::MixedPostQuantum`],
/// [`CoreError::Io`], or an [`age::EncryptError`].
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    to: To<'_>,
    armor: bool,
    on_progress: ProgressFn<'_>,
) -> Result<()> {
    let total = fs::metadata(input).map_err(io_at(input))?.len();
    let source = File::open(input).map_err(io_at(input))?;
    let mut reader = BufReader::with_capacity(CHUNK, source);

    let encryptor = match to {
        To::Recipients(rs) => {
            if rs.is_empty() {
                return Err(CoreError::NoRecipients);
            }
            let pq = rs.iter().filter(|r| r.kind.is_post_quantum()).count();
            if pq != 0 && pq != rs.len() {
                return Err(CoreError::MixedPostQuantum);
            }
            age::Encryptor::with_recipients(rs.iter().map(|r| r.recipient.as_ref() as _))?
        }
        To::Passphrase(p) => crate::passphrase::encryptor(p)?,
    };

    let (guard, sink) = TempOut::create(output)?;

    if armor {
        let armored = ArmoredWriter::wrap_output(sink, Format::AsciiArmor)?;
        let armored = pump(encryptor, armored, &mut reader, total, on_progress)?;
        let mut sink = armored.finish()?;
        sink.flush()?;
        sink.sync_all().map_err(io_at(output))?;
    } else {
        let mut sink = pump(encryptor, sink, &mut reader, total, on_progress)?;
        sink.flush()?;
        sink.sync_all().map_err(io_at(output))?;
    }

    guard.commit()
}

/// Wrap `sink`, copy the whole of `reader` through it, and finish the stream.
fn pump<W: Write, R: Read>(
    encryptor: age::Encryptor,
    sink: W,
    reader: &mut R,
    total: u64,
    on_progress: ProgressFn<'_>,
) -> Result<W> {
    let mut writer = encryptor.wrap_output(sink)?;
    let mut buf = vec![0_u8; CHUNK];
    let mut done: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(buf.get(..n).ok_or_else(|| {
            CoreError::BareIo(std::io::Error::other("short read exceeded buffer"))
        })?)?;
        done = done.saturating_add(n as u64);
        let frac = if total == 0 {
            1.0
        } else {
            (done as f32 / total as f32).clamp(0.0, 1.0)
        };
        if !on_progress(frac) {
            return Err(CoreError::Cancelled);
        }
    }

    // Must be called, or the file is truncated and will not decrypt.
    Ok(writer.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_is_a_sibling_dotfile_not_in_tmp() {
        let p = sibling_temp(Path::new("/home/kevin/Documents/report.pdf.age"));
        assert_eq!(
            p,
            PathBuf::from("/home/kevin/Documents/.report.pdf.age.agepony-partial")
        );
        assert!(!p.starts_with("/tmp"));
    }

    #[test]
    fn unique_path_leaves_a_free_path_alone() {
        let p = std::env::temp_dir().join("agepony-definitely-not-there.age");
        let _ = fs::remove_file(&p);
        assert_eq!(unique_path(&p), p);
    }

    #[test]
    fn unique_path_sidesteps_an_existing_file() {
        let dir = std::env::temp_dir().join("agepony-unique");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");

        let first = dir.join("notes.txt.age");
        fs::write(&first, b"x").expect("write");
        let second = unique_path(&first);
        assert_eq!(second, dir.join("notes (2).txt.age"));

        fs::write(&second, b"x").expect("write");
        assert_eq!(unique_path(&first), dir.join("notes (3).txt.age"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_path_keeps_double_extensions_together() {
        let dir = std::env::temp_dir().join("agepony-unique-tar");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("archive.tar.gz");
        fs::write(&p, b"x").expect("write");
        assert_eq!(unique_path(&p), dir.join("archive (2).tar.gz"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_uncommitted_temp_out_removes_itself() {
        let dir = std::env::temp_dir().join("agepony-drop-test");
        let _ = fs::create_dir_all(&dir);
        let target = dir.join("thing.age");
        let tmp = sibling_temp(&target);
        {
            let (_guard, _file) = TempOut::create(&target).expect("create");
            assert!(tmp.exists(), "temp file should exist while the guard lives");
        }
        assert!(!tmp.exists(), "temp file must be gone after drop");
        assert!(!target.exists(), "target must never have been created");
    }
}
