//! Wire envelope: an encrypted cell plus the sender's ephemeral
//! public key.
//!
//! `Session::establish` derives `cell_key` from (sender ephemeral
//! secret, recipient public key). The recipient can only derive the
//! matching key if it knows that same ephemeral public key — which,
//! for a genuinely separate receiving process, it can only learn if
//! it travels with the message. This is what actually gets sent as a
//! circuit's final `Deliver` body, not the raw encrypted cell alone.

use thiserror::Error;
use x25519_dalek::PublicKey;

use veil_core::crypto::ENCRYPTED_CELL_SIZE;

/// Total size of a wire envelope: a 32-byte X25519 public key
/// followed by an encrypted cell.
pub const ENVELOPE_SIZE: usize = 32 + ENCRYPTED_CELL_SIZE;

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("envelope has the wrong length: expected {expected}, got {actual}")]
    WrongLength { expected: usize, actual: usize },
}

/// Wraps an encrypted cell with the sender's ephemeral public key.
pub fn wrap(
    sender_public: &PublicKey,
    encrypted_cell: &[u8; ENCRYPTED_CELL_SIZE],
) -> [u8; ENVELOPE_SIZE] {
    let mut out = [0u8; ENVELOPE_SIZE];
    out[..32].copy_from_slice(sender_public.as_bytes());
    out[32..].copy_from_slice(encrypted_cell);
    out
}

/// Splits a received envelope back into the sender's ephemeral public
/// key and the still-encrypted cell, ready for the recipient to
/// derive the matching key and decrypt.
pub fn unwrap(envelope: &[u8]) -> Result<(PublicKey, [u8; ENCRYPTED_CELL_SIZE]), EnvelopeError> {
    if envelope.len() != ENVELOPE_SIZE {
        return Err(EnvelopeError::WrongLength {
            expected: ENVELOPE_SIZE,
            actual: envelope.len(),
        });
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&envelope[..32]);
    let public = PublicKey::from(pub_bytes);

    let mut cell_bytes = [0u8; ENCRYPTED_CELL_SIZE];
    cell_bytes.copy_from_slice(&envelope[32..]);

    Ok((public, cell_bytes))
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;
    use veil_core::crypto::KeyPair;

    #[test]
    fn wrap_then_unwrap_roundtrips() {
        let sender = KeyPair::generate(&mut OsRng);
        let fake_encrypted = [7u8; ENCRYPTED_CELL_SIZE];

        let envelope = wrap(&sender.public_key(), &fake_encrypted);
        let (recovered_public, recovered_cell) = unwrap(&envelope).unwrap();

        assert_eq!(recovered_public.as_bytes(), sender.public_key().as_bytes());
        assert_eq!(recovered_cell, fake_encrypted);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(unwrap(&[0u8; 10]).is_err());
    }

    #[test]
    fn envelope_is_exactly_the_advertised_size() {
        let sender = KeyPair::generate(&mut OsRng);
        let envelope = wrap(&sender.public_key(), &[0u8; ENCRYPTED_CELL_SIZE]);
        assert_eq!(envelope.len(), ENVELOPE_SIZE);
    }
}
