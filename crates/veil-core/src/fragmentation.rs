//! Splits arbitrary-length messages into fixed-size [`Cell`]s.

use rand::{CryptoRng, RngCore};

use crate::cell::{Cell, MessageId, PAYLOAD_CAPACITY};
use crate::error::{VeilError, VeilResult};

/// Maximum message size this crate will fragment, chosen so the
/// resulting cell count never exceeds what a `u16` sequence counter
/// can address (65,535 cells).
pub const MAX_MESSAGE_SIZE: usize = PAYLOAD_CAPACITY * u16::MAX as usize;

/// Splits an arbitrary-length message into a sequence of fixed-size
/// cells.
///
/// Every cell produced is exactly [`crate::cell::CELL_SIZE`] bytes once
/// serialized, regardless of the original message length — a one-byte
/// message and a one-megabyte message are visually indistinguishable
/// on the wire except for cell *count*, which routing and timing
/// obfuscation are responsible for hiding at a higher layer.
///
/// A random [`MessageId`] is generated per call so the receiver can
/// group and reassemble cells that may arrive out of order or
/// interleaved with unrelated traffic.
pub fn fragment_message(
    message: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> VeilResult<Vec<Cell>> {
    if message.is_empty() {
        return Err(VeilError::MessageTooLarge { len: 0, max: MAX_MESSAGE_SIZE });
    }
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(VeilError::MessageTooLarge {
            len: message.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }

    let mut message_id: MessageId = [0u8; 16];
    rng.fill_bytes(&mut message_id);

    let total_cells = message.len().div_ceil(PAYLOAD_CAPACITY);
    let seq_total = total_cells as u16;

    let mut cells = Vec::with_capacity(total_cells);
    for (i, chunk) in message.chunks(PAYLOAD_CAPACITY).enumerate() {
        let cell = Cell::new_data(message_id, i as u16, seq_total, chunk)?;
        cells.push(cell);
    }

    Ok(cells)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn single_cell_for_small_message() {
        let mut rng = OsRng;
        let cells = fragment_message(b"tiny", &mut rng).unwrap();
        assert_eq!(cells.len(), 1);
    }

    #[test]
    fn multi_cell_for_large_message() {
        let message = vec![7u8; PAYLOAD_CAPACITY * 3 + 10];
        let mut rng = OsRng;
        let cells = fragment_message(&message, &mut rng).unwrap();
        assert_eq!(cells.len(), 4);
        // Every cell must share the same message id.
        let id = cells[0].message_id();
        assert!(cells.iter().all(|c| c.message_id() == id));
    }

    #[test]
    fn empty_message_rejected() {
        let mut rng = OsRng;
        assert!(fragment_message(&[], &mut rng).is_err());
    }

    #[test]
    fn exact_multiple_of_capacity_does_not_produce_empty_trailing_cell() {
        let message = vec![1u8; PAYLOAD_CAPACITY * 2];
        let mut rng = OsRng;
        let cells = fragment_message(&message, &mut rng).unwrap();
        assert_eq!(cells.len(), 2);
    }
}
