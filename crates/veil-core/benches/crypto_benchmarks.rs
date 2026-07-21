//! Performance benchmarks for the hot path every cell goes through:
//! fragmentation, per-cell AEAD encryption/decryption, key exchange,
//! and reassembly. Run with `cargo bench -p veil-core`.
//!
//! These exist to catch performance regressions and to give an honest
//! answer to "how fast is this, actually" — a privacy layer that adds
//! imperceptible overhead is a very different claim from one that
//! merely compiles.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;

use veil_core::cell::Cell;
use veil_core::crypto::{decrypt_cell, encrypt_cell, KeyPair};
use veil_core::fragment_message;

fn bench_fragmentation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fragment_message");

    for size_kib in [1usize, 16, 64, 256] {
        let message = vec![0x42u8; size_kib * 1024];
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size_kib}KiB")),
            &message,
            |b, msg| {
                let mut rng = OsRng;
                b.iter(|| black_box(fragment_message(msg, &mut rng).unwrap()));
            },
        );
    }
    group.finish();
}

fn bench_single_cell_encryption(c: &mut Criterion) {
    let key = [7u8; 32];
    let cell = Cell::new_data(
        [1u8; 16],
        0,
        1,
        b"benchmark payload of representative length",
    )
    .unwrap();

    c.bench_function("encrypt_cell", |b| {
        b.iter(|| black_box(encrypt_cell(&key, &cell).unwrap()));
    });
}

fn bench_single_cell_decryption(c: &mut Criterion) {
    let key = [7u8; 32];
    let cell = Cell::new_data(
        [1u8; 16],
        0,
        1,
        b"benchmark payload of representative length",
    )
    .unwrap();
    let encrypted = encrypt_cell(&key, &cell).unwrap();

    c.bench_function("decrypt_cell", |b| {
        b.iter(|| black_box(decrypt_cell(&key, &encrypted).unwrap()));
    });
}

fn bench_key_exchange(c: &mut Criterion) {
    let mut rng = OsRng;
    let alice = KeyPair::generate(&mut rng);
    let bob = KeyPair::generate(&mut rng);
    let bob_public = bob.public_key();

    c.bench_function("x25519_diffie_hellman", |b| {
        b.iter(|| black_box(alice.diffie_hellman(&bob_public)));
    });

    c.bench_function("hkdf_derive_key", |b| {
        let shared = alice.diffie_hellman(&bob_public);
        b.iter(|| black_box(shared.derive_key(b"bench-context").unwrap()));
    });
}

/// The realistic end-to-end shape: fragment a message, then encrypt
/// every resulting cell — what `VeilClient::send` actually does per
/// message, minus the network round-trips.
fn bench_full_send_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("send_pipeline_fragment_and_encrypt");

    for size_kib in [1usize, 16, 64] {
        let message = vec![0x99u8; size_kib * 1024];
        let key = [3u8; 32];
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size_kib}KiB")),
            &message,
            |b, msg| {
                let mut rng = OsRng;
                b.iter(|| {
                    let cells = fragment_message(msg, &mut rng).unwrap();
                    for cell in &cells {
                        black_box(encrypt_cell(&key, cell).unwrap());
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_fragmentation,
    bench_single_cell_encryption,
    bench_single_cell_decryption,
    bench_key_exchange,
    bench_full_send_pipeline,
);
criterion_main!(benches);
