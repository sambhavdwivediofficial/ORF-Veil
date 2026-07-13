//! Integration tests exercising `veil-core` entirely through its
//! public API, the way a downstream crate (`veil-sdk`, `veil-relay`)
//! would use it.

use rand::rngs::OsRng;
use veil_core::crypto::{decrypt_cell, encrypt_cell, KeyPair};
use veil_core::{fragment_message, Cell, Reassembler};

#[test]
fn fragment_and_reassemble_roundtrip() {
    let message = b"The quick brown fox jumps over the lazy dog, repeated for length. ".repeat(20);

    let mut rng = OsRng;
    let cells = fragment_message(&message, &mut rng).expect("fragmentation should succeed");
    assert!(cells.len() > 1, "message should span multiple cells");

    let mut reassembler = Reassembler::new();
    let mut output = None;
    for cell in cells {
        if let Some(msg) = reassembler.insert(cell).expect("insert should succeed") {
            output = Some(msg);
        }
    }

    assert_eq!(output.expect("message should be complete"), message);
}

#[test]
fn reassembly_handles_out_of_order_cells() {
    let message = b"out of order delivery test payload spanning several cells of data".repeat(30);
    let mut rng = OsRng;
    let mut cells = fragment_message(&message, &mut rng).unwrap();

    // Reverse arrival order to simulate independently-routed cells
    // taking different paths through the relay fabric.
    cells.reverse();

    let mut reassembler = Reassembler::new();
    let mut output = None;
    for cell in cells {
        if let Some(msg) = reassembler.insert(cell).unwrap() {
            output = Some(msg);
        }
    }

    assert_eq!(output.unwrap(), message);
}

#[test]
fn single_cell_message_roundtrip() {
    let message = b"short message";
    let mut rng = OsRng;
    let cells = fragment_message(message, &mut rng).unwrap();
    assert_eq!(cells.len(), 1);

    let mut reassembler = Reassembler::new();
    let result = reassembler
        .insert(cells.into_iter().next().unwrap())
        .unwrap();
    assert_eq!(result.unwrap(), message);
}

#[test]
fn empty_message_is_rejected() {
    let mut rng = OsRng;
    assert!(fragment_message(&[], &mut rng).is_err());
}

#[test]
fn encrypt_decrypt_roundtrip_between_two_parties() {
    let mut rng = OsRng;
    let alice = KeyPair::generate(&mut rng);
    let bob = KeyPair::generate(&mut rng);

    let shared_a = alice.diffie_hellman(&bob.public_key());
    let shared_b = bob.diffie_hellman(&alice.public_key());

    let key_a = shared_a.derive_key(b"veil-cell-encryption-v1").unwrap();
    let key_b = shared_b.derive_key(b"veil-cell-encryption-v1").unwrap();
    assert_eq!(key_a, key_b, "both sides must derive an identical key");

    let cell = Cell::new_data([7u8; 16], 0, 1, b"hello veil").unwrap();

    let encrypted = encrypt_cell(&key_a, &cell).unwrap();
    let decrypted = decrypt_cell(&key_b, &encrypted).unwrap();

    assert_eq!(decrypted.payload(), b"hello veil");
}

#[test]
fn decryption_fails_with_wrong_key() {
    let key_a = [1u8; 32];
    let key_b = [2u8; 32];

    let cell = Cell::new_data([0u8; 16], 0, 1, b"secret").unwrap();
    let encrypted = encrypt_cell(&key_a, &cell).unwrap();

    assert!(decrypt_cell(&key_b, &encrypted).is_err());
}

#[test]
fn dummy_and_data_cells_are_structurally_identical_in_size() {
    let mut rng = OsRng;
    let dummy = Cell::new_dummy(&mut rng);
    let real = Cell::new_data([9u8; 16], 0, 1, b"data").unwrap();

    assert_eq!(dummy.to_bytes().len(), real.to_bytes().len());
}
