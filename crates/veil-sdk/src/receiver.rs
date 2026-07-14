//! Client-side message receiving.
//!
//! A recipient has no way to know in advance which relay a given
//! message will exit through — path selection is random and chosen
//! by the sender (see `veil-routing::path_selection`). So a receiving
//! client polls every relay it knows about and attempts to decrypt
//! everything it gets back. Cells not addressed to this identity
//! simply fail to decrypt and are discarded — there is no way to tell
//! from the ciphertext alone who a cell was meant for, which is
//! exactly the property this system is built around (see
//! THREAT_MODEL.md).

use thiserror::Error;

use veil_core::crypto::{decrypt_cell, KeyPair};
use veil_core::Cell;
use veil_relay::pull_listener;

use crate::envelope;

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("network error talking to a relay mailbox: {0}")]
    Io(#[from] std::io::Error),
}

/// Polls every address in `mailbox_addrs` once and returns every cell
/// among their queued deliveries that successfully decrypts under
/// `identity`'s private key.
///
/// This does not fragment/reassemble multi-cell messages that exited
/// through different relays — see `ROADMAP.md`. Each returned `Cell`
/// is one fragment.
pub async fn receive(
    identity: &KeyPair,
    mailbox_addrs: &[String],
) -> Result<Vec<Cell>, ReceiveError> {
    let mut decrypted = Vec::new();

    for addr in mailbox_addrs {
        let envelopes = pull_listener::pull(addr).await?;

        for raw in envelopes {
            let Ok((sender_public, encrypted)) = envelope::unwrap(&raw) else {
                continue; // not a validly-sized envelope — ignore and move on
            };

            let shared = identity.diffie_hellman(&sender_public);
            let Ok(key) = shared.derive_key(b"veil-sdk-session-v1") else {
                continue;
            };

            // A decryption failure here just means this cell wasn't
            // addressed to `identity` — not an error condition.
            if let Ok(cell) = decrypt_cell(&key, &encrypted) {
                decrypted.push(cell);
            }
        }
    }

    Ok(decrypted)
}
