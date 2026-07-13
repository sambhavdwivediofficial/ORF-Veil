//! Per-conversation session state.
//!
//! A `Session` should be created once per recipient, not reused across
//! unrelated conversations — the derived `cell_key` is specific to the
//! (sender ephemeral key, recipient identity key) pair it came from.

use rand::rngs::OsRng;
use x25519_dalek::PublicKey;

use veil_core::crypto::KeyPair;
use veil_core::VeilError;

pub struct Session {
    keypair: KeyPair,
    pub(crate) cell_key: [u8; 32],
}

impl Session {
    /// Establishes a session with a recipient identified by their
    /// long-term public key, deriving a shared symmetric key via
    /// X25519 + HKDF-SHA256. The recipient derives the identical key
    /// on their side using their private key and this session's
    /// [`Session::public_key`].
    pub fn establish(recipient_public: &PublicKey) -> Result<Self, VeilError> {
        let keypair = KeyPair::generate(&mut OsRng);
        let shared = keypair.diffie_hellman(recipient_public);
        let cell_key = shared.derive_key(b"veil-sdk-session-v1")?;
        Ok(Self { keypair, cell_key })
    }

    /// This session's ephemeral public key. Share it with the
    /// recipient so they can derive the same `cell_key`.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn sender_and_recipient_derive_the_same_key() {
        let recipient = KeyPair::generate(&mut OsRng);
        let session = Session::establish(&recipient.public_key()).unwrap();

        let recipient_shared = recipient.diffie_hellman(&session.public_key());
        let recipient_key = recipient_shared.derive_key(b"veil-sdk-session-v1").unwrap();

        assert_eq!(session.cell_key, recipient_key);
    }
}
