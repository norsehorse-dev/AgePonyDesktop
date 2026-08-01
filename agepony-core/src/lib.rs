//! AgePony Desktop core.
//!
//! Pure crypto and file handling. Knows nothing about egui, and must never
//! learn. Everything here is synchronous and blocking; the desktop crate is
//! responsible for keeping it off the UI thread.
//!
//! # Layout
//!
//! - [`identity`] — generating, parsing and storing identities
//! - [`recipient`] — parsing recipient strings, classical and post-quantum
//! - [`book`] — the named recipient book (public key material only)
//! - [`store`] — the identity store: labels, dates, the active identity
//! - [`passphrase`] — the scrypt work factor AgePony writes and accepts
//! - [`porting`] — receiving an identity from a phone
//! - [`vault`] — keeping the store and the book consistent with each other
//! - [`encrypt`] / [`decrypt`] — streaming file operations with progress
//! - [`pq`] — the standardised `mlkem768x25519` recipient (Phase 4)

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The deny(unwrap_used) lints in Cargo.toml are for production paths. Tests are
// allowed to assert loudly -- a panic in a test IS the failure report.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod book;
pub mod clock;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod identity;
pub mod passphrase;
pub mod porting;
pub mod pq;
pub mod recipient;
pub mod store;
pub mod vault;

pub use error::{CoreError, Result};

/// Buffer size for streaming copies. One age payload chunk is 64 KiB; matching
/// it keeps the STREAM implementation from doing partial-chunk work.
pub const CHUNK: usize = 64 * 1024;

/// A progress callback. Receives a fraction in `0.0..=1.0`.
///
/// Returning `false` asks the operation to abort; it will unwind, clean up any
/// partial output, and return [`CoreError::Cancelled`].
pub type ProgressFn<'a> = &'a mut dyn FnMut(f32) -> bool;
