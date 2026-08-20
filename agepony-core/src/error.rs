//! Typed errors for `agepony-core`.
//!
//! These cross the crate boundary, so they are `thiserror` enums rather than
//! `anyhow`. The UI crate is free to wrap them in `anyhow::Error`.

use std::path::PathBuf;

/// Anything that can go wrong in the core.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// An I/O error, annotated with the path it happened on.
    #[error("{path}: {source}")]
    Io {
        /// The file being read or written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// An I/O error with no meaningful path (in-memory operations).
    #[error(transparent)]
    BareIo(#[from] std::io::Error),

    /// The `age` crate refused to encrypt.
    #[error(transparent)]
    Encrypt(#[from] age::EncryptError),

    /// The `age` crate refused to decrypt. Includes wrong-identity and
    /// authentication failures.
    #[error(transparent)]
    Decrypt(#[from] age::DecryptError),

    /// A recipient string was not a recognised age recipient.
    #[error("not a valid age recipient: {0}")]
    InvalidRecipient(String),

    /// An identity string was not a recognised age identity.
    #[error("not a valid age identity")]
    InvalidIdentity,

    /// The identity file contained no usable identities.
    #[error("no identities found in identity file")]
    NoIdentities,

    /// Encrypting with no recipients would produce a file nobody can open.
    #[error("no recipients selected")]
    NoRecipients,

    /// The recipient book on disk was not valid JSON, or was the wrong shape.
    #[error("recipient book is corrupt: {0}")]
    CorruptBook(#[from] serde_json::Error),

    /// A post-quantum recipient was mixed with a classical one. age enforces
    /// this via stanza labels; we surface it before the user hits it.
    #[error("post-quantum recipients cannot be combined with classical recipients")]
    MixedPostQuantum,

    /// The identity file is passphrase protected and no passphrase was given.
    #[error("this identity file is protected by a passphrase")]
    PassphraseRequired,

    /// The store already holds an identity with this label.
    #[error("an identity called \"{0}\" already exists")]
    DuplicateLabel(String),

    /// No identity in the store matches the given id.
    #[error("no such identity")]
    NoSuchIdentity,

    /// The operation was cancelled from the UI.
    #[error("cancelled")]
    Cancelled,

    /// Reached code that Phase 4 has to fill in.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),

    /// A key was offered for signing that cannot sign (an age X25519 or
    /// post-quantum identity, or an unsupported SSH algorithm).
    #[error("this key cannot sign: {0}")]
    UnsupportedSigningKey(String),

    /// Signing or verification failed inside the SSH layer.
    #[error("signing failed: {0}")]
    Signing(String),

    /// A signature blob was not a well-formed SSHSIG.
    #[error("not a valid SSH signature")]
    InvalidSignature,
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Attach a path to an [`std::io::Error`].
pub(crate) fn io_at(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> CoreError {
    move |source| CoreError::Io {
        path: path.into(),
        source,
    }
}
