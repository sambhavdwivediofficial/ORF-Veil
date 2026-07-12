//! Fixed-size cell format used throughout the Veil relay fabric.
//!
//! Every message is fragmented into cells of identical size before
//! entering the network. This uniformity is a core privacy property:
//! an observer watching the wire cannot distinguish cells by size,
//! regardless of how large or small the original message was, and
//! cannot distinguish real data cells from dummy cover traffic without
//! the decryption key.

use rand::{CryptoRng, RngCore};

use crate::error::{VeilError, VeilResult};

/// Total size, in bytes, of a single Veil cell on the wire in its
/// plaintext (pre-encryption) form. This value is fixed for the
/// lifetime of protocol version [`PROTOCOL_VERSION`] and MUST be
/// identical for every cell in the network, real or dummy.
pub const CELL_SIZE: usize = 512;

/// Size of the fixed cell header, in bytes.
///
/// Layout: version(1) + cell_type(1) + message_id(16) + seq_index(2)
/// + seq_total(2) + payload_len(2) = 24 bytes.
pub const HEADER_SIZE: usize = 24;

/// Maximum number of real payload bytes a single cell can carry.
pub const PAYLOAD_CAPACITY: usize = CELL_SIZE - HEADER_SIZE;

/// Current wire protocol version. Bumped on any breaking change to the
/// cell layout.
pub const PROTOCOL_VERSION: u8 = 1;

/// Identifies whether a cell carries real application data or is
/// injected purely to obscure traffic patterns (cover traffic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    Data = 0,
    Dummy = 1,
}

impl CellType {
    fn from_u8(v: u8) -> VeilResult<Self> {
        match v {
            0 => Ok(CellType::Data),
            1 => Ok(CellType::Dummy),
            other => Err(VeilError::InvalidCellType(other)),
        }
    }
}

/// A unique identifier grouping all cells that belong to the same
/// original message, letting a receiver reassemble fragments that may
/// arrive out of order or interleaved with unrelated traffic.
pub type MessageId = [u8; 16];

/// A single, fixed-size cell — the atomic unit of transport in Veil.
///
/// Every cell, whether carrying real data or dummy padding, is exactly
/// [`CELL_SIZE`] bytes once serialized via [`Cell::to_bytes`]. There is
/// no code path in this type that produces a cell of any other size.
#[derive(Debug, Clone)]
pub struct Cell {
    version: u8,
    cell_type: CellType,
    message_id: MessageId,
    seq_index: u16,
    seq_total: u16,
    payload_len: u16,
    payload: [u8; PAYLOAD_CAPACITY],
}

impl Cell {
    /// Construct a new data cell carrying one fragment of a larger
    /// message.
    ///
    /// `data` must fit within [`PAYLOAD_CAPACITY`] bytes; use
    /// [`crate::fragmentation::fragment_message`] to split larger
    /// messages into multiple cells first.
    pub fn new_data(
        message_id: MessageId,
        seq_index: u16,
        seq_total: u16,
        data: &[u8],
    ) -> VeilResult<Self> {
        if data.len() > PAYLOAD_CAPACITY {
            return Err(VeilError::PayloadTooLarge {
                len: data.len(),
                max: PAYLOAD_CAPACITY,
            });
        }
        if seq_total == 0 || seq_index >= seq_total {
            return Err(VeilError::InvalidSequence { seq_index, seq_total });
        }

        let mut payload = [0u8; PAYLOAD_CAPACITY];
        payload[..data.len()].copy_from_slice(data);

        Ok(Self {
            version: PROTOCOL_VERSION,
            cell_type: CellType::Data,
            message_id,
            seq_index,
            seq_total,
            payload_len: data.len() as u16,
            payload,
        })
    }

    /// Construct a dummy cell filled with cryptographically random
    /// bytes.
    ///
    /// Dummy cells are structurally identical to data cells — same
    /// size, same header layout, same encryption — so they cannot be
    /// distinguished on the wire without the decryption key. This is
    /// what makes cover traffic effective: it is not padding at the
    /// edges, it is indistinguishable noise mixed into the stream.
    pub fn new_dummy(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut message_id = [0u8; 16];
        rng.fill_bytes(&mut message_id);
        let mut payload = [0u8; PAYLOAD_CAPACITY];
        rng.fill_bytes(&mut payload);

        Self {
            version: PROTOCOL_VERSION,
            cell_type: CellType::Dummy,
            message_id,
            seq_index: 0,
            seq_total: 1,
            payload_len: PAYLOAD_CAPACITY as u16,
            payload,
        }
    }

    pub fn cell_type(&self) -> CellType {
        self.cell_type
    }

    pub fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn seq_index(&self) -> u16 {
        self.seq_index
    }

    pub fn seq_total(&self) -> u16 {
        self.seq_total
    }

    /// Returns the real payload bytes only, excluding trailing padding.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// Serialize this cell into its fixed-size wire representation.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut buf = [0u8; CELL_SIZE];
        buf[0] = self.version;
        buf[1] = self.cell_type as u8;
        buf[2..18].copy_from_slice(&self.message_id);
        buf[18..20].copy_from_slice(&self.seq_index.to_be_bytes());
        buf[20..22].copy_from_slice(&self.seq_total.to_be_bytes());
        buf[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[HEADER_SIZE..].copy_from_slice(&self.payload);
        buf
    }

    /// Parse a cell from its fixed-size wire representation.
    ///
    /// Validates the protocol version, cell type, payload length bound,
    /// and sequence fields before accepting the cell — malformed or
    /// adversarially crafted input is rejected here rather than
    /// propagating further into the system.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> VeilResult<Self> {
        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(VeilError::UnsupportedVersion(version));
        }

        let cell_type = CellType::from_u8(buf[1])?;

        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&buf[2..18]);

        let seq_index = u16::from_be_bytes([buf[18], buf[19]]);
        let seq_total = u16::from_be_bytes([buf[20], buf[21]]);
        let payload_len = u16::from_be_bytes([buf[22], buf[23]]);

        if payload_len as usize > PAYLOAD_CAPACITY {
            return Err(VeilError::PayloadTooLarge {
                len: payload_len as usize,
                max: PAYLOAD_CAPACITY,
            });
        }
        if seq_total == 0 || seq_index >= seq_total {
            return Err(VeilError::InvalidSequence { seq_index, seq_total });
        }

        let mut payload = [0u8; PAYLOAD_CAPACITY];
        payload.copy_from_slice(&buf[HEADER_SIZE..]);

        Ok(Self {
            version,
            cell_type,
            message_id,
            seq_index,
            seq_total,
            payload_len,
            payload,
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn data_cell_roundtrip_preserves_payload() {
        let id = [1u8; 16];
        let cell = Cell::new_data(id, 0, 1, b"hello").unwrap();
        let bytes = cell.to_bytes();
        let parsed = Cell::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload(), b"hello");
        assert_eq!(parsed.message_id(), id);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let data = vec![0u8; PAYLOAD_CAPACITY + 1];
        let result = Cell::new_data([0u8; 16], 0, 1, &data);
        assert!(matches!(result, Err(VeilError::PayloadTooLarge { .. })));
    }

    #[test]
    fn invalid_sequence_is_rejected() {
        let result = Cell::new_data([0u8; 16], 5, 3, b"x");
        assert!(matches!(result, Err(VeilError::InvalidSequence { .. })));
    }

    #[test]
    fn every_cell_serializes_to_exactly_cell_size() {
        let data_cell = Cell::new_data([0u8; 16], 0, 1, b"short").unwrap();
        let dummy_cell = Cell::new_dummy(&mut OsRng);
        assert_eq!(data_cell.to_bytes().len(), CELL_SIZE);
        assert_eq!(dummy_cell.to_bytes().len(), CELL_SIZE);
    }
}
