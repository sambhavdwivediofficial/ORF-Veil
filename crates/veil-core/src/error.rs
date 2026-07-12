//! Central error type for `veil-core`.
//!
//! Every fallible operation in this crate returns [`VeilResult`]. Error
//! variants are deliberately specific enough to debug locally but never
//! leak information across a trust boundary that could help an attacker
//! (see [`VeilError::DecryptionFailed`] in particular).

use thiserror::Error;

/// Convenience alias used throughout `veil-core`.
pub type VeilResult<T> = Result<T, VeilError>;

#[derive(Debug, Error)]
pub enum VeilError {
    #[error("payload of {len} bytes exceeds maximum cell capacity of {max} bytes")]
    PayloadTooLarge { len: usize, max: usize },

    #[error("invalid cell sequence: index {seq_index} of total {seq_total}")]
    InvalidSequence { seq_index: u16, seq_total: u16 },

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid cell type byte: {0}")]
    InvalidCellType(u8),

    #[error("message size {len} bytes exceeds maximum of {max} bytes")]
    MessageTooLarge { len: usize, max: usize },

    #[error("incomplete message: received {received} of {expected} cells")]
    IncompleteMessage { received: usize, expected: usize },

    #[error("cell belongs to a different message than expected")]
    MismatchedMessageId,

    #[error("cell encryption failed")]
    EncryptionFailed,

    /// Deliberately vague: an AEAD decryption can fail because the key is
    /// wrong, the ciphertext was corrupted in transit, or it was forged
    /// by an attacker. A relay or client must never be able to
    /// distinguish these cases from the error alone — doing so would
    /// leak an oracle an attacker could use to probe the network.
    #[error("decryption failed: invalid key, corrupted data, or forged ciphertext")]
    DecryptionFailed,

    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),
}
