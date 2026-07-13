//! Cryptographic primitives used by the Veil fabric: X25519 key
//! exchange and ChaCha20-Poly1305 authenticated encryption of cells.

pub mod encryption;
pub mod keys;

pub use encryption::{decrypt_cell, encrypt_cell, ENCRYPTED_CELL_SIZE, NONCE_SIZE, TAG_SIZE};
pub use keys::{public_key_from_bytes, public_key_to_hex, KeyPair, SharedSecret};
