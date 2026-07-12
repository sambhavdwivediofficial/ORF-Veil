//! Onion-layer packet format: construction, peeling, and framed I/O.
//!
//! A relay only ever sees the single layer addressed to it. Peeling
//! that layer with the relay's static key reveals either the next hop
//! to forward the (still-opaque) body to, or a `Deliver` marker if
//! this relay is the circuit's exit point. No relay sees the full
//! path, the originating sender, or the plaintext of a `Forward` body.
//!
//! v1 limitation: layer size is not padded to be constant across hop
//! depth, so cell size can leak approximate circuit position to a
//! passive observer. Fixed-size Sphinx-style padding is planned; see
//! THREAT_MODEL.md.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use veil_core::crypto::KeyPair;

const EPHEMERAL_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const ONION_KEY_CONTEXT: &[u8] = b"veil-onion-layer-v1";

#[derive(Debug, Error)]
pub enum OnionError {
    #[error("frame too short to contain an onion layer")]
    FrameTooShort,
    #[error("layer decryption failed: wrong key, corrupted, or forged")]
    DecryptionFailed,
    #[error("malformed onion payload")]
    Malformed,
    #[error("key derivation failed")]
    KeyDerivation,
}

pub enum OnionPayload {
    Forward { next_hop: String, body: Vec<u8> },
    Deliver { body: Vec<u8> },
}

/// Build a single onion layer addressed to `relay_public`. Used by the
/// sender (`veil-sdk`) to wrap each hop of a circuit, innermost layer
/// first, so only the intended relay can peel it.
pub fn build_onion_layer(
    relay_public: &PublicKey,
    payload: &OnionPayload,
) -> Result<Vec<u8>, OnionError> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(relay_public);
    let key = derive_key_from_bytes(shared.as_bytes())?;

    let plaintext = encode_payload(payload);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|_| OnionError::KeyDerivation)?;

    let mut out = Vec::with_capacity(EPHEMERAL_KEY_SIZE + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Peel the outer onion layer using this relay's static keypair.
pub fn peel_onion_layer(keypair: &KeyPair, frame: &[u8]) -> Result<OnionPayload, OnionError> {
    if frame.len() < EPHEMERAL_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(OnionError::FrameTooShort);
    }

    let mut ephemeral_bytes = [0u8; EPHEMERAL_KEY_SIZE];
    ephemeral_bytes.copy_from_slice(&frame[..EPHEMERAL_KEY_SIZE]);
    let ephemeral_public = PublicKey::from(ephemeral_bytes);

    let shared = keypair.diffie_hellman(&ephemeral_public);
    let key = shared.derive_key(ONION_KEY_CONTEXT).map_err(|_| OnionError::KeyDerivation)?;

    let nonce = Nonce::from_slice(&frame[EPHEMERAL_KEY_SIZE..EPHEMERAL_KEY_SIZE + NONCE_SIZE]);
    let ciphertext = &frame[EPHEMERAL_KEY_SIZE + NONCE_SIZE..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| OnionError::DecryptionFailed)?;

    decode_payload(&plaintext)
}

/// Mirrors `SharedSecret::derive_key` in `veil-core`, operating on raw
/// DH output instead of the wrapper type — needed here because the
/// sender uses an ephemeral `x25519_dalek::StaticSecret` directly
/// rather than a full `veil_core::crypto::KeyPair`.
fn derive_key_from_bytes(shared_secret: &[u8; 32]) -> Result<[u8; 32], OnionError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(ONION_KEY_CONTEXT, &mut okm).map_err(|_| OnionError::KeyDerivation)?;
    Ok(okm)
}

fn encode_payload(payload: &OnionPayload) -> Vec<u8> {
    match payload {
        OnionPayload::Forward { next_hop, body } => {
            let hop_bytes = next_hop.as_bytes();
            let mut out = Vec::with_capacity(3 + hop_bytes.len() + body.len());
            out.push(0u8);
            out.extend_from_slice(&(hop_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(hop_bytes);
            out.extend_from_slice(body);
            out
        }
        OnionPayload::Deliver { body } => {
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(1u8);
            out.extend_from_slice(body);
            out
        }
    }
}

fn decode_payload(bytes: &[u8]) -> Result<OnionPayload, OnionError> {
    let (&flag, rest) = bytes.split_first().ok_or(OnionError::Malformed)?;
    match flag {
        0 => {
            if rest.len() < 2 {
                return Err(OnionError::Malformed);
            }
            let hop_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            let rest = &rest[2..];
            if rest.len() < hop_len {
                return Err(OnionError::Malformed);
            }
            let next_hop =
                String::from_utf8(rest[..hop_len].to_vec()).map_err(|_| OnionError::Malformed)?;
            let body = rest[hop_len..].to_vec();
            Ok(OnionPayload::Forward { next_hop, body })
        }
        1 => Ok(OnionPayload::Deliver { body: rest.to_vec() }),
        _ => Err(OnionError::Malformed),
    }
}

/// Write a length-prefixed frame: 4-byte big-endian length + body.
pub async fn write_frame(
    writer: &mut (impl AsyncWriteExt + Unpin),
    body: &[u8],
) -> std::io::Result<()> {
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(body).await
}

/// Read a length-prefixed frame written by [`write_frame`].
pub async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng as StdOsRng;

    #[test]
    fn forward_layer_roundtrip() {
        let mut rng = StdOsRng;
        let relay = KeyPair::generate(&mut rng);

        let payload = OnionPayload::Forward {
            next_hop: "127.0.0.1:9002".to_string(),
            body: b"opaque inner frame".to_vec(),
        };
        let frame = build_onion_layer(&relay.public_key(), &payload).unwrap();
        let peeled = peel_onion_layer(&relay, &frame).unwrap();

        match peeled {
            OnionPayload::Forward { next_hop, body } => {
                assert_eq!(next_hop, "127.0.0.1:9002");
                assert_eq!(body, b"opaque inner frame");
            }
            _ => panic!("expected Forward variant"),
        }
    }

    #[test]
    fn deliver_layer_roundtrip() {
        let mut rng = StdOsRng;
        let relay = KeyPair::generate(&mut rng);

        let payload = OnionPayload::Deliver { body: b"final cell bytes".to_vec() };
        let frame = build_onion_layer(&relay.public_key(), &payload).unwrap();
        let peeled = peel_onion_layer(&relay, &frame).unwrap();

        match peeled {
            OnionPayload::Deliver { body } => assert_eq!(body, b"final cell bytes"),
            _ => panic!("expected Deliver variant"),
        }
    }

    #[test]
    fn wrong_relay_key_fails_to_peel() {
        let mut rng = StdOsRng;
        let relay = KeyPair::generate(&mut rng);
        let attacker = KeyPair::generate(&mut rng);

        let payload = OnionPayload::Deliver { body: b"secret".to_vec() };
        let frame = build_onion_layer(&relay.public_key(), &payload).unwrap();

        assert!(peel_onion_layer(&attacker, &frame).is_err());
    }

    #[tokio::test]
    async fn frame_roundtrip_over_a_pipe() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_frame(&mut client, b"hello relay").await.unwrap();
        let received = read_frame(&mut server).await.unwrap();
        assert_eq!(received, b"hello relay");
    }
}
