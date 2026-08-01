//! Non-GUI verbs, for verifying a packaged build.
//!
//! # Why these exist, given the plan says no CLI
//!
//! They are not a CLI. `rage` is the CLI and this does not compete with it —
//! there is no verb here that encrypts or decrypts a file the user names.
//!
//! They exist because a packaged GUI binary can build perfectly, install
//! perfectly, and fail to start. A missing X11, Wayland or GL shared library on
//! the target, or a glibc floor higher than the user's distribution, produces
//! an artifact that passes every unit test — because unit tests run on the
//! build machine — and then does nothing when double-clicked. Nothing in a
//! `cargo test` run can catch that. Something that runs *the shipped binary on
//! the target* can.
//!
//! So: three read-only verbs, each chosen for what it proves about a packaged
//! image rather than for what a user would want.
//!
//! | verb | what it proves |
//! |---|---|
//! | `version` | the binary starts, links, and reports the toolchain that built it |
//! | `selftest` | the crypto works in *this* build, not just in the test suite |
//! | `list-recipients` | the config directory and JSON store open outside a dev environment |
//!
//! # Windows
//!
//! A GUI-subsystem process on Windows has no stdout, so every verb here would
//! run and silently discard its output. PGPony shipped exactly that. The GUI
//! binary keeps `windows_subsystem = "windows"` and stays windowless; a second
//! binary, `agepony-cli`, omits the attribute and is console-subsystem. On
//! macOS and Linux there is no such split and the one binary does both.

use agepony_core::book::Book;
use agepony_core::store::{Kind, Store};
use std::fmt::Write as _;

/// The compiler that built this binary, from `build.rs`.
pub const RUSTC: &str = env!("AGEPONY_RUSTC");
/// The target triple this binary was built for.
pub const TARGET: &str = env!("AGEPONY_TARGET");
/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run a verb.
///
/// Returns `None` if there is nothing to do and the GUI should start, or
/// `Some(exit_code)` if a verb ran.
#[must_use]
pub fn run(args: &[String]) -> Option<i32> {
    let verb = args.first()?.as_str();
    Some(match verb {
        "version" | "--version" | "-V" => {
            println!("{}", version_line());
            0
        }
        "selftest" => selftest(),
        "list-recipients" | "list" => list_recipients(),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            0
        }
        other => {
            eprintln!("unknown verb: {other}\n\n{}", usage());
            2
        }
    })
}

/// `AgePony Desktop 0.1.0 (rustc 1.95.0 …, x86_64-unknown-linux-gnu)`
#[must_use]
pub fn version_line() -> String {
    format!("AgePony Desktop {VERSION} ({RUSTC}, {TARGET})")
}

fn usage() -> String {
    format!(
        "AgePony Desktop {VERSION}\n\
         \n\
         Run with no arguments to open the app.\n\
         \n\
         These verbs exist to verify a packaged build; they never read or write\n\
         a file you name. For encrypting and decrypting from a terminal, use rage.\n\
         \n\
         \x20 version           print the version and the toolchain that built it\n\
         \x20 selftest          exercise the crypto in this build and report PASS or FAIL\n\
         \x20 list-recipients   print the recipient book, proving the store opens\n"
    )
}

/// Exercise the crypto in *this* binary.
///
/// Prints one line per check so a failure names itself. The whole value is
/// learning which check broke on a machine you cannot attach a debugger to.
fn selftest() -> i32 {
    println!("{}", version_line());

    /// One selftest check: a name, and something that either explains what it
    /// proved or why it failed.
    type Check = (&'static str, fn() -> Result<String, String>);

    let checks: [Check; 6] = [
        ("classic round trip", check_classic),
        ("post-quantum round trip", check_post_quantum),
        ("passphrase round trip", check_passphrase),
        ("post-quantum reference vector", check_pq_vector),
        ("bech32 round trip", check_bech32),
        ("config directory", check_config_dir),
    ];

    let mut failed = 0;
    for (name, check) in checks {
        match check() {
            Ok(detail) => println!("PASS - {name}: {detail}"),
            Err(why) => {
                println!("FAIL - {name}: {why}");
                failed += 1;
            }
        }
    }

    if failed == 0 {
        println!("PASS - all {} checks", checks.len());
        0
    } else {
        println!("FAIL - {failed} of {} checks", checks.len());
        1
    }
}

fn round_trip(kind: Kind) -> Result<String, String> {
    let identity = match kind {
        Kind::X25519 => {
            use age::secrecy::ExposeSecret as _;
            let id = agepony_core::identity::generate_x25519();
            (
                id.to_public().to_string(),
                id.to_string().expose_secret().to_owned(),
            )
        }
        Kind::PostQuantum => {
            let id = agepony_core::identity::generate_pq().map_err(|e| e.to_string())?;
            (
                id.to_public().map_err(|e| e.to_string())?.to_string(),
                id.to_bech32().map_err(|e| e.to_string())?.to_string(),
            )
        }
    };

    let dir = std::env::temp_dir().join("agepony-selftest");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let plain = dir.join("selftest.txt");
    let ct = dir.join("selftest.txt.age");
    let back = dir.join("selftest.back");
    for f in [&plain, &ct, &back] {
        let _ = std::fs::remove_file(f);
    }

    let message = b"AgePony selftest";
    std::fs::write(&plain, message).map_err(|e| e.to_string())?;

    let recipients =
        agepony_core::recipient::parse_all([identity.0.as_str()]).map_err(|e| e.to_string())?;
    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .map_err(|e| e.to_string())?;

    let ids = agepony_core::identity::parse_identities(&identity.1).map_err(|e| e.to_string())?;
    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    )
    .map_err(|e| e.to_string())?;

    let got = std::fs::read(&back).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);

    if got == message {
        Ok(format!("{} bytes", got.len()))
    } else {
        Err("plaintext did not survive the round trip".to_owned())
    }
}

fn check_classic() -> Result<String, String> {
    round_trip(Kind::X25519)
}

fn check_post_quantum() -> Result<String, String> {
    round_trip(Kind::PostQuantum)
}

fn check_passphrase() -> Result<String, String> {
    use age::secrecy::SecretString;

    let dir = std::env::temp_dir().join("agepony-selftest-pass");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let plain = dir.join("p.txt");
    let ct = dir.join("p.txt.age");
    let back = dir.join("p.back");
    for f in [&plain, &ct, &back] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&plain, b"passphrase selftest").map_err(|e| e.to_string())?;

    let pass = SecretString::from("agepony selftest passphrase");
    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Passphrase(pass.clone()),
        true,
        &mut |_| true,
    )
    .map_err(|e| e.to_string())?;
    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Passphrase(pass),
        &mut |_| true,
    )
    .map_err(|e| e.to_string())?;

    let ok = std::fs::read(&back).map_err(|e| e.to_string())? == b"passphrase selftest";
    let _ = std::fs::remove_dir_all(&dir);
    if ok {
        Ok("armored".to_owned())
    } else {
        Err("plaintext did not survive".to_owned())
    }
}

/// The post-quantum known-answer vector, checked inside the shipped binary.
///
/// The test suite already checks this. Repeating it here checks something
/// different: that *this build* — these compiler flags, this architecture —
/// still derives the reference key. It is the one check that would catch an
/// ML-KEM implementation behaving differently on aarch64, which is a real
/// possibility for lattice code and invisible to a test suite that only ever
/// runs on the build machine.
///
/// The expected value is read out of `vectors/agepony-vectors.json` at compile
/// time rather than transcribed. The first version of this function carried
/// hand-copied head and tail bytes and the tail was misaligned by one nibble —
/// caught only because the check ran. Embedding the file makes that class of
/// mistake unconstructible, and keeps one source of truth across the three
/// platforms.
fn check_pq_vector() -> Result<String, String> {
    const VECTORS: &str = include_str!("../../vectors/agepony-vectors.json");

    let parsed: serde_json::Value =
        serde_json::from_str(VECTORS).map_err(|e| format!("vectors file is unreadable: {e}"))?;
    let kat = parsed
        .pointer("/mlkem768x25519/kat")
        .ok_or_else(|| "vectors file has no mlkem768x25519 known-answer vector".to_owned())?;

    let seed = hex(kat
        .get("seed")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default())?;
    let expected = hex(kat
        .get("expected_public_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default())?;

    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "the vector's seed is not 32 bytes".to_owned())?;
    let key = agepony_core::pq::xwing::PrivateKey::from_seed(&seed);

    if key.public_key().as_slice() != expected.as_slice() {
        return Err(format!(
            "derived key does not match the reference ({} bytes expected)",
            expected.len()
        ));
    }
    Ok(format!("mlkem768x25519, {} bytes match", expected.len()))
}

/// Decode a lowercase hex string.
fn hex(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err(format!("bad hex length {}", s.len()));
    }
    let value = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("bad hex digit {:?}", c as char)),
        }
    };
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(value(p[0])? << 4 | value(p[1])?))
        .collect()
}

fn check_bech32() -> Result<String, String> {
    let identity = agepony_core::identity::generate_pq().map_err(|e| e.to_string())?;
    let recipient = identity.to_public().map_err(|e| e.to_string())?.to_string();
    let parsed = agepony_core::recipient::parse(&recipient).map_err(|e| e.to_string())?;
    if !parsed.kind.is_post_quantum() {
        return Err("a post-quantum recipient did not parse as one".to_owned());
    }
    // Uppercase is what the QR code carries.
    agepony_core::recipient::parse(&recipient.to_uppercase()).map_err(|e| e.to_string())?;
    Ok(format!("{} characters, both cases", recipient.len()))
}

fn check_config_dir() -> Result<String, String> {
    let dir = crate::app::config_dir();
    let parent = dir
        .parent()
        .ok_or_else(|| "config directory has no parent".to_owned())?;
    if !parent.exists() && std::fs::create_dir_all(parent).is_err() {
        return Err(format!("cannot create {}", parent.display()));
    }
    Ok(dir.display().to_string())
}

/// Print the recipient book.
///
/// The only verb that opens the store and the JSON on disk, which is the one
/// part of the app a packaged build could break independently of the crypto.
/// Prints to stderr when empty, so an empty result pipes as zero lines.
fn list_recipients() -> i32 {
    let dir = crate::app::config_dir();

    let store = match Store::open(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not open the identity store: {e}");
            return 1;
        }
    };
    let book = match Book::load(&dir.join("recipients.json")) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("could not open the recipient book: {e}");
            return 1;
        }
    };

    if book.entries.is_empty() {
        eprintln!("No recipients on this machine.");
        return 0;
    }

    let mut out = String::new();
    for entry in book.sorted() {
        let kind = agepony_core::recipient::parse(&entry.recipient).map_or("unreadable", |p| {
            if p.kind.is_post_quantum() {
                "post-quantum"
            } else {
                "classic"
            }
        });
        let own = if entry.is_own() {
            " (this machine)"
        } else {
            ""
        };
        let _ = writeln!(out, "{}\t{kind}{own}\t{}", entry.name, entry.recipient);
    }
    print!("{out}");
    eprintln!(
        "{} recipient(s), {} identity(ies) on this machine",
        book.entries.len(),
        store.entries().len()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_line_reports_the_toolchain() {
        let line = version_line();
        assert!(line.starts_with("AgePony Desktop "));
        assert!(line.contains("rustc"), "no compiler in {line}");
        // Check the constants, not the rendered line: every Linux and Windows
        // target triple contains the literal "unknown" (x86_64-unknown-linux-gnu),
        // so a substring test here fails on a perfectly good stamp. What this is
        // actually guarding is build.rs falling back, which makes the whole value
        // the word.
        assert_ne!(
            RUSTC, "unknown",
            "build.rs could not read the compiler version"
        );
        assert_ne!(TARGET, "unknown", "build.rs could not read the target");
        assert!(line.contains(VERSION));
    }

    #[test]
    fn selftest_passes_in_this_build() {
        // The same thing CI asserts on every shipped artifact.
        assert_eq!(selftest(), 0);
    }

    #[test]
    fn no_arguments_means_open_the_gui() {
        assert!(run(&[]).is_none());
    }

    #[test]
    fn an_unknown_verb_exits_non_zero_rather_than_starting_the_gui() {
        // Otherwise a typo in a script silently opens a window on a headless box.
        assert_eq!(run(&["nonsense".to_owned()]), Some(2));
    }
}
