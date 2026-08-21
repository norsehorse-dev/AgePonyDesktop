//! Background worker.
//!
//! egui redraws on one thread and must never block. Every encrypt or decrypt
//! runs on a worker; the UI keeps the receiving end of a channel and drains it
//! once per frame.
//!
//! ```text
//! UI thread                     Worker thread
//! ---------                     -------------
//! spawn(Job)  ─────────────►    for each file:
//!                                 open, stream through age, rename on success
//! drain()     ◄─────────────    Started(path) / Progress(f32)
//! drain()     ◄─────────────    FileDone(path) | FileFailed(path, why)
//! drain()     ◄─────────────    Finished
//! ```
//!
//! Note what is *not* here: no `Arc<Mutex<AppState>>`. The job owns everything
//! it needs, because it was moved in. That is the ownership model doing its
//! job, and it is the main thing that feels different from `@Published`.
//!
//! **One bad file does not stop the batch.** A failure is recorded and the
//! worker moves on; cancellation stops everything. Aborting ten files because
//! the third was unreadable would be the wrong trade.

use age::secrecy::SecretString;
use agepony_core::archive::tar;
use agepony_core::decrypt::{With, decrypt_file};
use agepony_core::encrypt::{To, encrypt_bytes_to_file, encrypt_file, unique_path};
use agepony_core::recipient::Parsed;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

/// How the batch should be protected.
pub enum Lock {
    /// To parsed recipients.
    Recipients(Vec<Parsed>),
    /// To a passphrase.
    Passphrase(SecretString),
}

/// What the worker is being asked to do.
pub enum Job {
    /// Encrypt every file in `inputs`.
    Encrypt {
        /// Source files.
        inputs: Vec<PathBuf>,
        /// Recipients or a passphrase.
        lock: Lock,
        /// ASCII armor the output.
        armor: bool,
    },
    /// Bundle every file in `inputs` into one compact-USTAR archive and encrypt
    /// that to a single `.tar.age`, so a set of files travels as one file.
    EncryptBundle {
        /// Source files, in archive order.
        inputs: Vec<PathBuf>,
        /// Recipients or a passphrase.
        lock: Lock,
        /// ASCII armor the output.
        armor: bool,
        /// The `.tar.age` to write.
        output: PathBuf,
    },
    /// Decrypt every file in `inputs`.
    Decrypt {
        /// Source files.
        inputs: Vec<PathBuf>,
        /// Identity files to try, or a passphrase.
        unlock: Unlock,
    },
    /// Re-encrypt every file in `inputs` to `target`, into `dest_dir` — the
    /// "upgrade to quantum-safe" batch. Originals are left untouched.
    Migrate {
        /// Source `.age` files.
        inputs: Vec<PathBuf>,
        /// The target recipient string (a post-quantum `age1pq1…`).
        target: String,
        /// Identity files to decrypt the inputs with.
        identity_files: Vec<PathBuf>,
        /// A shared passphrase for passphrase-encrypted inputs.
        passphrase: Option<SecretString>,
        /// Where the re-encrypted copies are written.
        dest_dir: PathBuf,
    },
}

/// How a decrypt batch should be unlocked.
pub enum Unlock {
    /// Identity files, with an optional passphrase for any that are protected.
    Identities {
        /// Files to load.
        files: Vec<PathBuf>,
        /// Unlocks any of them that are passphrase protected. Loading happens
        /// on the worker, not the UI thread, because scrypt is deliberately
        /// slow — that is the point of it — and a second of frozen window is
        /// exactly what egui punishes you for.
        passphrase: Option<SecretString>,
    },
    /// A passphrase-encrypted file, no identity involved.
    Passphrase(SecretString),
}

/// What the worker reports back.
enum Update {
    Started(PathBuf),
    /// Progress through the CURRENT file, 0..1. The worker does not know or
    /// care about the batch; `Running::drain` turns this into an overall
    /// fraction, and the per-row display uses it as it is.
    Progress(f32),
    /// Input that finished, and where its output landed. Both ends, because
    /// the queue keys rows by input and the reveal button wants the output.
    FileDone(PathBuf, PathBuf),
    FileFailed(PathBuf, String),
    Finished,
}

/// One finished file.
pub struct Outcome {
    /// The input it came from. This is the key the queue looks rows up by.
    pub input: PathBuf,
    /// Where the output landed.
    pub output: PathBuf,
}

/// A running (or finished) batch.
pub struct Running {
    rx: Receiver<Update>,
    cancel: Arc<AtomicBool>,
    total: usize,
    /// Overall fraction complete across the whole batch.
    pub progress: f32,
    /// Fraction complete of the file in `current`, 0..1.
    pub file_progress: f32,
    /// The file currently being worked on.
    pub current: Option<PathBuf>,
    /// Outputs written so far.
    pub done: Vec<Outcome>,
    /// Inputs that failed, with why.
    pub failed: Vec<(PathBuf, String)>,
    /// Whether the batch has stopped.
    pub finished: bool,
}

impl Running {
    /// Ask the worker to stop at the next chunk boundary.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether work is still in flight.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        !self.finished
    }

    /// How many files were queued.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }

    /// A one-line summary once finished.
    #[must_use]
    pub fn summary(&self) -> String {
        summarise(self.done.len(), self.failed.len())
    }

    /// Drain everything the worker has sent since the last frame.
    ///
    /// Returns `true` if anything changed, which is the cue to repaint.
    pub fn drain(&mut self) -> bool {
        let mut changed = false;
        loop {
            match self.rx.try_recv() {
                Ok(Update::Started(p)) => {
                    self.current = Some(p);
                    self.file_progress = 0.0;
                    changed = true;
                }
                Ok(Update::Progress(f)) => {
                    self.file_progress = f;
                    self.progress = overall(self.done.len() + self.failed.len(), f, self.total);
                    changed = true;
                }
                Ok(Update::FileDone(input, output)) => {
                    self.done.push(Outcome { input, output });
                    self.file_progress = 0.0;
                    self.progress = overall(self.done.len() + self.failed.len(), 0.0, self.total);
                    changed = true;
                }
                Ok(Update::FileFailed(input, why)) => {
                    self.failed.push((input, why));
                    self.file_progress = 0.0;
                    self.progress = overall(self.done.len() + self.failed.len(), 0.0, self.total);
                    changed = true;
                }
                Ok(Update::Finished) => {
                    self.finished = true;
                    self.current = None;
                    self.progress = 1.0;
                    changed = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if !self.finished {
                        self.finished = true;
                        self.failed
                            .push((PathBuf::new(), "worker stopped unexpectedly".to_owned()));
                        changed = true;
                    }
                    break;
                }
            }
        }
        changed
    }
}

/// The batch summary line. Free-standing so it can be tested without a worker.
#[must_use]
pub fn summarise(written: usize, failed: usize) -> String {
    match (written, failed) {
        (0, 0) => "Nothing to do".to_owned(),
        (1, 0) => "1 file written".to_owned(),
        (n, 0) => format!("{n} files written"),
        (0, 1) => "Failed".to_owned(),
        (0, f) => format!("All {f} files failed"),
        (n, f) => format!("{n} written, {f} failed"),
    }
}

/// Spawn `job` on a worker thread.
///
/// `repaint` is called whenever the worker sends an update, so egui wakes
/// instead of waiting for the next input event.
pub fn spawn(job: Job, repaint: impl Fn() + Send + 'static) -> Running {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);

    let total = match &job {
        Job::Encrypt { inputs, .. }
        | Job::Decrypt { inputs, .. }
        | Job::EncryptBundle { inputs, .. }
        | Job::Migrate { inputs, .. } => inputs.len(),
    };

    std::thread::spawn(move || {
        let send = |u: Update| {
            let ok = tx.send(u).is_ok();
            repaint();
            ok
        };

        match job {
            Job::Encrypt {
                inputs,
                lock,
                armor,
            } => {
                for input in &inputs {
                    if worker_cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = send(Update::Started(input.clone()));

                    let mut output = input.clone().into_os_string();
                    output.push(".age");
                    let output = unique_path(Path::new(&output));

                    let to = match &lock {
                        Lock::Recipients(r) => To::Recipients(r),
                        Lock::Passphrase(p) => To::Passphrase(p.clone()),
                    };

                    let mut on_progress = file_progress(&tx, &worker_cancel);
                    let result = encrypt_file(input, &output, to, armor, &mut on_progress);
                    report(&send, input, &output, result);
                }
            }
            Job::EncryptBundle {
                inputs,
                lock,
                armor,
                output,
            } => {
                let _ = send(Update::Started(output.clone()));

                // Build the tar in memory. A set chosen to travel together is
                // modest; the ciphertext still streams to disk.
                let mut entries: Vec<tar::Entry> = Vec::new();
                let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut read_error = None;
                for input in &inputs {
                    match std::fs::read(input) {
                        Ok(data) => entries.push(tar::Entry {
                            name: unique_entry_name(input, &mut used),
                            data,
                        }),
                        Err(e) => {
                            read_error = Some(format!("could not read {}: {e}", input.display()));
                            break;
                        }
                    }
                }

                let result = if let Some(why) = read_error {
                    Err(why)
                } else {
                    tar::create(&entries)
                        .map_err(|e| e.to_string())
                        .and_then(|tarball| {
                            let out = unique_path(&output);
                            let to = match &lock {
                                Lock::Recipients(r) => To::Recipients(r),
                                Lock::Passphrase(p) => To::Passphrase(p.clone()),
                            };
                            let mut on_progress = file_progress(&tx, &worker_cancel);
                            encrypt_bytes_to_file(&tarball, &out, to, armor, &mut on_progress)
                                .map(|()| out)
                                .map_err(|e| e.to_string())
                        })
                };

                // Resolve every contributing row to the one bundle output.
                match result {
                    Ok(out) => {
                        for input in &inputs {
                            let _ = send(Update::FileDone(input.clone(), out.clone()));
                        }
                    }
                    Err(why) => {
                        for input in &inputs {
                            let _ = send(Update::FileFailed(input.clone(), why.clone()));
                        }
                    }
                }
            }
            Job::Decrypt { inputs, unlock } => {
                // Load identities once for the whole batch. scrypt on an
                // encrypted identity file is slow by design; doing it per file
                // would multiply that by the queue length for no reason.
                let identities = match &unlock {
                    Unlock::Identities { files, passphrase } => {
                        let mut loaded: Vec<Box<dyn age::Identity + Send + Sync>> = Vec::new();
                        let mut err = None;
                        for f in files {
                            match agepony_core::identity::load_file_maybe_encrypted(
                                f,
                                passphrase.as_ref(),
                            ) {
                                Ok(mut v) => loaded.append(&mut v),
                                Err(e) => err = Some(e),
                            }
                        }
                        if loaded.is_empty() {
                            let why = err.map_or_else(
                                || "no identities found".to_owned(),
                                |e| e.to_string(),
                            );
                            for input in &inputs {
                                let _ = send(Update::FileFailed(input.clone(), why.clone()));
                            }
                            let _ = send(Update::Finished);
                            return;
                        }
                        Some(loaded)
                    }
                    Unlock::Passphrase(_) => None,
                };

                for input in &inputs {
                    if worker_cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = send(Update::Started(input.clone()));

                    let output = unique_path(&agepony_core::decrypt::default_output_path(input));
                    let with = match (&identities, &unlock) {
                        (Some(ids), _) => With::Identities(ids),
                        (None, Unlock::Passphrase(p)) => With::Passphrase(p.clone()),
                        (None, Unlock::Identities { .. }) => unreachable!("handled above"),
                    };

                    let mut on_progress = file_progress(&tx, &worker_cancel);
                    let result = decrypt_file(input, &output, with, &mut on_progress);
                    report(&send, input, &output, result);
                }
            }
            Job::Migrate {
                inputs,
                target,
                identity_files,
                passphrase,
                dest_dir,
            } => {
                let target = match agepony_core::recipient::parse(&target) {
                    Ok(t) => t,
                    Err(e) => {
                        for input in &inputs {
                            let _ = send(Update::FileFailed(input.clone(), e.to_string()));
                        }
                        let _ = send(Update::Finished);
                        return;
                    }
                };
                // Load the unprotected identities once; scrypt on a protected
                // identity per file would be pointless work, and the flow uses
                // the shared passphrase for passphrase-encrypted inputs instead.
                let mut identities: Vec<Box<dyn age::Identity + Send + Sync>> = Vec::new();
                for f in &identity_files {
                    if let Ok(mut v) = agepony_core::identity::load_file_maybe_encrypted(f, None) {
                        identities.append(&mut v);
                    }
                }

                for input in &inputs {
                    if worker_cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = send(Update::Started(input.clone()));
                    let result =
                        std::fs::read(input)
                            .map_err(|e| e.to_string())
                            .and_then(|bytes| {
                                agepony_core::migrate::reencrypt(
                                    &bytes,
                                    &identities,
                                    passphrase.as_ref(),
                                    &target,
                                )
                                .map_err(|e| e.to_string())
                            });
                    match result {
                        Ok(out_bytes) => {
                            let name = input.file_name().map_or_else(
                                || "file.age".to_owned(),
                                |n| n.to_string_lossy().into_owned(),
                            );
                            let out = unique_path(&dest_dir.join(name));
                            match std::fs::write(&out, out_bytes) {
                                Ok(()) => {
                                    let _ = send(Update::FileDone(input.clone(), out));
                                }
                                Err(e) => {
                                    let _ = send(Update::FileFailed(input.clone(), e.to_string()));
                                }
                            }
                        }
                        Err(why) => {
                            let _ = send(Update::FileFailed(input.clone(), why));
                        }
                    }
                }
            }
        }

        let _ = send(Update::Finished);
    });

    Running {
        rx,
        cancel,
        total,
        progress: 0.0,
        file_progress: 0.0,
        current: None,
        done: Vec::new(),
        failed: Vec::new(),
        finished: false,
    }
}

/// The whole batch's fraction, from how many files are settled and how far the
/// current one has got. Free-standing so it can be tested without a worker.
#[must_use]
pub fn overall(settled: usize, file_fraction: f32, total: usize) -> f32 {
    if total == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let raw = (settled as f32 + file_fraction.clamp(0.0, 1.0)) / total as f32;
    raw.clamp(0.0, 1.0)
}

/// One file's 0..1 progress, throttled to whole percents. A 4 GB file at
/// 64 KiB a chunk is ~65k callbacks; sending each one would spend more time in
/// the channel than in ChaCha20.
fn file_progress<'a>(
    tx: &'a std::sync::mpsc::Sender<Update>,
    cancel: &'a Arc<AtomicBool>,
) -> impl FnMut(f32) -> bool + 'a {
    let mut last_pct: i32 = -1;
    move |f: f32| {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        #[allow(clippy::cast_possible_truncation)]
        let pct = (f * 100.0) as i32;
        if pct != last_pct {
            last_pct = pct;
            return tx.send(Update::Progress(f)).is_ok();
        }
        true
    }
}

/// The tar entry name for `input`: its file name, made unique within the archive
/// by inserting ` (2)` before the extension if the name is already taken, so two
/// files that share a basename do not clobber each other on extraction.
fn unique_entry_name(input: &Path, used: &mut std::collections::HashSet<String>) -> String {
    let base = input
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
    if used.insert(base.clone()) {
        return base;
    }
    let (stem, ext) = match base.find('.') {
        Some(i) if i > 0 => (&base[..i], &base[i..]),
        _ => (base.as_str(), ""),
    };
    for n in 2..10_000 {
        let candidate = format!("{stem} ({n}){ext}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    base
}

fn report(
    send: &impl Fn(Update) -> bool,
    input: &Path,
    output: &Path,
    result: agepony_core::Result<()>,
) {
    let _ = match result {
        Ok(()) => send(Update::FileDone(input.to_path_buf(), output.to_path_buf())),
        Err(e) => send(Update::FileFailed(input.to_path_buf(), e.to_string())),
    };
}

/// Open the OS file manager with `path` selected.
pub fn reveal(path: &Path) {
    let dir = path.parent().unwrap_or(path);
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_progress_walks_the_batch_monotonically() {
        // Empty batch is complete, not NaN: this is the 0/0 case again.
        assert!((overall(0, 0.0, 0) - 1.0).abs() < f32::EPSILON);
        // Second file of four, half done: 1.5/4.
        assert!((overall(1, 0.5, 4) - 0.375).abs() < 1e-6);
        // A rogue per-file fraction cannot push the batch past 1.
        assert!(overall(3, 7.0, 4) <= 1.0);
        assert!(overall(9, 0.0, 4) <= 1.0);
    }

    #[test]
    fn the_summary_reads_naturally_at_every_count() {
        assert_eq!(summarise(0, 0), "Nothing to do");
        assert_eq!(summarise(1, 0), "1 file written");
        assert_eq!(summarise(7, 0), "7 files written");
        assert_eq!(summarise(0, 1), "Failed");
        assert_eq!(summarise(0, 4), "All 4 files failed");
        // Partial failure has to be visible: a batch that says "3 files
        // written" while silently dropping two is the worst outcome here.
        assert_eq!(summarise(3, 2), "3 written, 2 failed");
    }
}
