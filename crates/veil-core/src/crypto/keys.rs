//! X25519 key exchange and key derivation.

use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{VeilError, VeilResult};

/// Overwrite a byte buffer with zeros in a way the compiler is
/// guaranteed not to optimize away, even though the buffer is about to
/// be dropped. Plain assignment (`buf = [0u8; N]`) can legally be
/// elided by the optimizer since the value is otherwise unused; a
/// volatile write cannot.
fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned `&mut u8` for the
        // duration of this call, which is all `write_volatile` requires.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A long-term or ephemeral X25519 keypair used to derive shared
/// secrets between a client and a relay or destination, without any
/// intermediate relay ever learning the private key.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair using a cryptographically secure
    /// RNG.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// This keypair's public key, safe to transmit to peers.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Perform a Diffie-Hellman exchange with a peer's public key,
    /// producing a shared secret.
    ///
    /// The private key never leaves this struct; only the resulting
    /// [`SharedSecret`] is returned.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.secret.diffie_hellman(peer_public).to_bytes())
    }
}

/// A raw 32-byte shared secret produced by a Diffie-Hellman exchange.
///
/// This type is deliberately not `Clone` or `Copy`, and its contents
/// are wiped from memory when it is dropped, since it is sensitive key
/// material that should never outlive its intended scope.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Derive a 32-byte symmetric key from this shared secret using
    /// HKDF-SHA256.
    ///
    /// `context` binds the derived key to a specific purpose (domain
    /// separation) — using a different context string for, e.g., cell
    /// encryption versus a MAC key ensures the two derived keys are
    /// cryptographically independent even though they come from the
    /// same underlying shared secret.
    pub fn derive_key(&self, context: &[u8]) -> VeilResult<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(context, &mut okm)
            .map_err(|_| VeilError::InvalidKey("HKDF expand failed: invalid output length"))?;
        Ok(okm)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

/// Parse a public key from its 32-byte wire representation, as
/// received from a peer.
pub fn public_key_from_bytes(bytes: [u8; 32]) -> PublicKey {
    PublicKey::from(bytes)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn both_sides_derive_identical_shared_key() {
        let mut rng = OsRng;
        let alice = KeyPair::generate(&mut rng);
        let bob = KeyPair::generate(&mut rng);

        let shared_alice = alice.diffie_hellman(&bob.public_key());
        let shared_bob = bob.diffie_hellman(&alice.public_key());

        let key_alice = shared_alice.derive_key(b"test-context").unwrap();
        let key_bob = shared_bob.derive_key(b"test-context").unwrap();

        assert_eq!(key_alice, key_bob);
    }

    #[test]
    fn different_contexts_derive_different_keys() {
        let mut rng = OsRng;
        let alice = KeyPair::generate(&mut rng);
        let bob = KeyPair::generate(&mut rng);
        let shared = alice.diffie_hellman(&bob.public_key());

        let key_a = shared.derive_key(b"context-a").unwrap();
        let key_b = shared.derive_key(b"context-b").unwrap();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn different_keypairs_derive_different_shared_secrets() {
        let mut rng = OsRng;
        let alice = KeyPair::generate(&mut rng);
        let bob = KeyPair::generate(&mut rng);
        let mallory = KeyPair::generate(&mut rng);

        let alice_bob = alice.diffie_hellman(&bob.public_key()).derive_key(b"ctx").unwrap();
        let alice_mallory =
            alice.diffie_hellman(&mallory.public_key()).derive_key(b"ctx").unwrap();

        assert_ne!(alice_bob, alice_mallory);
    }
}
