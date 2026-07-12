//! Per-cell authenticated encryption using ChaCha20-Poly1305.

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::cell::{Cell, CELL_SIZE};
use crate::error::{VeilError, VeilResult};

/// Length, in bytes, of the random nonce prepended to every ciphertext.
pub const NONCE_SIZE: usize = 12;

/// Length, in bytes, of the Poly1305 authentication tag appended by
/// the AEAD construction.
pub const TAG_SIZE: usize = 16;

/// Total size of an encrypted cell on the wire: nonce + ciphertext +
/// authentication tag.
pub const ENCRYPTED_CELL_SIZE: usize = NONCE_SIZE + CELL_SIZE + TAG_SIZE;

/// Encrypt a single cell under a 256-bit key.
///
/// A fresh random nonce is generated on every call and prepended to
/// the output, so encrypting the same cell twice under the same key
/// never produces the same ciphertext — this is essential, since a
/// repeated ciphertext pattern would itself be a metadata leak an
/// observer could exploit.
pub fn encrypt_cell(key: &[u8; 32], cell: &Cell) -> VeilResult<[u8; ENCRYPTED_CELL_SIZE]> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cell.to_bytes();
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| VeilError::EncryptionFailed)?;

    let mut out = [0u8; ENCRYPTED_CELL_SIZE];
    out[..NONCE_SIZE].copy_from_slice(&nonce_bytes);
    out[NONCE_SIZE..].copy_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt and parse a cell produced by [`encrypt_cell`] under the same
/// key.
///
/// Returns [`VeilError::DecryptionFailed`] if the ciphertext was
/// tampered with, corrupted in transit, or encrypted under a different
/// key. The AEAD construction makes these cases indistinguishable by
/// design — a relay or client must never be able to tell an attacker
/// *why* a cell failed to decrypt, only *that* it did.
pub fn decrypt_cell(key: &[u8; 32], data: &[u8; ENCRYPTED_CELL_SIZE]) -> VeilResult<Cell> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
    let ciphertext = &data[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VeilError::DecryptionFailed)?;

    let mut buf = [0u8; CELL_SIZE];
    buf.copy_from_slice(&plaintext);
    Cell::from_bytes(&buf)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_recovers_original_cell() {
        let key = [42u8; 32];
        let cell = Cell::new_data([1u8; 16], 0, 1, b"veil payload").unwrap();

        let encrypted = encrypt_cell(&key, &cell).unwrap();
        let decrypted = decrypt_cell(&key, &encrypted).unwrap();

        assert_eq!(decrypted.payload(), b"veil payload");
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let cell = Cell::new_data([0u8; 16], 0, 1, b"secret").unwrap();

        let encrypted = encrypt_cell(&key_a, &cell).unwrap();
        let result = decrypt_cell(&key_b, &encrypted);

        assert!(matches!(result, Err(VeilError::DecryptionFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = [9u8; 32];
        let cell = Cell::new_data([0u8; 16], 0, 1, b"integrity check").unwrap();

        let mut encrypted = encrypt_cell(&key, &cell).unwrap();
        // Flip a bit in the ciphertext body (past the nonce).
        encrypted[NONCE_SIZE + 5] ^= 0x01;

        let result = decrypt_cell(&key, &encrypted);
        assert!(matches!(result, Err(VeilError::DecryptionFailed)));
    }

    #[test]
    fn repeated_encryption_of_same_cell_produces_different_ciphertext() {
        let key = [5u8; 32];
        let cell = Cell::new_data([0u8; 16], 0, 1, b"same content").unwrap();

        let first = encrypt_cell(&key, &cell).unwrap();
        let second = encrypt_cell(&key, &cell).unwrap();

        assert_ne!(first, second, "nonces must differ, so ciphertexts must differ");
    }
}
