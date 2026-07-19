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
use veil_core::{Cell, Reassembler};
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
/// Returns individual cell fragments, not reassembled messages — use
/// [`Receiver`] if a message may span more than one cell.
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

/// Stateful receiver that reassembles multi-cell messages across
/// repeated polls.
///
/// Every cell of a message takes an independent, randomly chosen path
/// (see `veil-sdk::client`), so different fragments of the same
/// message can exit through different relays and arrive at different
/// times. A single one-shot [`receive`] call cannot assume every
/// fragment of a message has landed yet — `Receiver` keeps a
/// [`Reassembler`] alive across calls to [`Receiver::poll`] so
/// fragments accumulate, however many polls it takes, until a message
/// is complete.
pub struct Receiver {
    identity: KeyPair,
    reassembler: Reassembler,
}

impl Receiver {
    pub fn new(identity: KeyPair) -> Self {
        Self {
            identity,
            reassembler: Reassembler::new(),
        }
    }

    /// Polls every relay in `mailbox_addrs` once, feeds any cells
    /// addressed to this identity into the internal reassembler, and
    /// returns every message that is now complete — possibly using
    /// fragments accumulated across earlier calls to this method.
    ///
    /// An empty result is not an error: it just means nothing
    /// completed this round, either because nothing arrived or
    /// because some fragments are still in transit on another relay.
    pub async fn poll(&mut self, mailbox_addrs: &[String]) -> Result<Vec<Vec<u8>>, ReceiveError> {
        let cells = receive(&self.identity, mailbox_addrs).await?;

        let mut completed = Vec::new();
        for cell in cells {
            // A cell that fails to insert (e.g. a corrupted or
            // adversarial mismatched message id) is simply dropped
            // rather than aborting the whole poll.
            if let Ok(Some(message)) = self.reassembler.insert(cell) {
                completed.push(message);
            }
        }
        Ok(completed)
    }

    /// Number of messages currently partially received and still
    /// waiting on more fragments.
    pub fn pending_count(&self) -> usize {
        self.reassembler.pending_count()
    }
}
