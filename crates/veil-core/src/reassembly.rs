//! Reconstructs original messages from cells received over the fabric.

use std::collections::HashMap;

use crate::cell::{Cell, MessageId};
use crate::error::{VeilError, VeilResult};

/// Accumulates cells belonging to in-flight messages and reassembles
/// each one once every fragment has arrived.
///
/// This type assumes it only ever receives real data cells for a
/// single logical stream — filtering out dummy cover-traffic cells and
/// demultiplexing streams is the responsibility of the caller (the
/// relay/client networking layer), keeping this type free of any I/O
/// or networking concerns.
#[derive(Default)]
pub struct Reassembler {
    in_flight: HashMap<MessageId, PartialMessage>,
}

struct PartialMessage {
    seq_total: u16,
    received: usize,
    fragments: Vec<Option<Vec<u8>>>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self { in_flight: HashMap::new() }
    }

    /// Feed a single received cell into the reassembler.
    ///
    /// Returns `Ok(Some(message))` once every fragment for that cell's
    /// message id has arrived, `Ok(None)` if the message is still
    /// incomplete, and `Err` if the cell is inconsistent with fragments
    /// already received for the same message id.
    ///
    /// Cells may be inserted in any order — reassembly does not assume
    /// sequential arrival, since cells for the same message travel
    /// independent, randomly-selected paths through the relay fabric.
    pub fn insert(&mut self, cell: Cell) -> VeilResult<Option<Vec<u8>>> {
        let id = cell.message_id();
        let seq_total = cell.seq_total();
        let seq_index = cell.seq_index() as usize;

        let entry = self.in_flight.entry(id).or_insert_with(|| PartialMessage {
            seq_total,
            received: 0,
            fragments: vec![None; seq_total as usize],
        });

        if entry.seq_total != seq_total {
            return Err(VeilError::MismatchedMessageId);
        }

        if entry.fragments[seq_index].is_none() {
            entry.fragments[seq_index] = Some(cell.payload().to_vec());
            entry.received += 1;
        }

        if entry.received == entry.seq_total as usize {
            let partial = self.in_flight.remove(&id).expect("entry was just accessed above");
            let mut message = Vec::new();
            for fragment in partial.fragments {
                message.extend_from_slice(&fragment.expect("all fragments verified present"));
            }
            return Ok(Some(message));
        }

        Ok(None)
    }

    /// Number of messages currently partially received and awaiting
    /// their remaining fragments.
    pub fn pending_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Discard an in-flight message that will never complete (e.g. a
    /// relay path was dropped, or a peer disconnected mid-transfer).
    ///
    /// Callers should invoke this periodically for stale entries to
    /// bound memory growth — this type has no built-in expiry, since
    /// timing policy belongs to the layer above.
    pub fn evict(&mut self, id: &MessageId) {
        self.in_flight.remove(id);
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn completes_after_all_fragments_received() {
        let id = [3u8; 16];
        let mut reassembler = Reassembler::new();

        let c0 = Cell::new_data(id, 0, 2, b"hel").unwrap();
        let c1 = Cell::new_data(id, 1, 2, b"lo").unwrap();

        assert!(reassembler.insert(c0).unwrap().is_none());
        let result = reassembler.insert(c1).unwrap();
        assert_eq!(result.unwrap(), b"hello");
    }

    #[test]
    fn duplicate_cell_does_not_corrupt_state() {
        let id = [4u8; 16];
        let mut reassembler = Reassembler::new();

        let c0 = Cell::new_data(id, 0, 2, b"a").unwrap();
        let c0_dup = Cell::new_data(id, 0, 2, b"a").unwrap();
        let c1 = Cell::new_data(id, 1, 2, b"b").unwrap();

        reassembler.insert(c0).unwrap();
        reassembler.insert(c0_dup).unwrap();
        let result = reassembler.insert(c1).unwrap();
        assert_eq!(result.unwrap(), b"ab");
    }

    #[test]
    fn mismatched_seq_total_is_rejected() {
        let id = [5u8; 16];
        let mut reassembler = Reassembler::new();

        let c0 = Cell::new_data(id, 0, 2, b"a").unwrap();
        let c1 = Cell::new_data(id, 0, 3, b"a").unwrap();

        reassembler.insert(c0).unwrap();
        let result = reassembler.insert(c1);
        assert!(matches!(result, Err(VeilError::MismatchedMessageId)));
    }

    #[test]
    fn evict_removes_pending_message() {
        let id = [6u8; 16];
        let mut reassembler = Reassembler::new();
        reassembler.insert(Cell::new_data(id, 0, 2, b"a").unwrap()).unwrap();
        assert_eq!(reassembler.pending_count(), 1);
        reassembler.evict(&id);
        assert_eq!(reassembler.pending_count(), 0);
    }
}
