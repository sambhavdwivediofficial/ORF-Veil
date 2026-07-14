//! Scheduled cover traffic.
//!
//! `veil_routing::dummy_traffic::DummyTrafficGenerator` already knows
//! how to produce a dummy cell at a randomized interval; this module
//! is what actually puts one on the wire on a running schedule,
//! wrapped exactly like a real send — same envelope size, same AEAD
//! construction, just encrypted under a throwaway key nobody holds —
//! so a relay or external observer cannot distinguish cover traffic
//! from a real message by its shape.

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use x25519_dalek::PublicKey;

use veil_core::crypto::encrypt_cell;
use veil_relay::forwarding::write_frame;
use veil_routing::build_circuit;
use veil_routing::dummy_traffic::DummyTrafficGenerator;
use veil_routing::path_selection::select_path;
use veil_routing::topology::Topology;

use crate::envelope;

/// Spawns a background task that continuously sends dummy cells
/// through freshly selected circuits at randomized intervals.
///
/// The returned handle keeps running until aborted — call
/// `.abort()` on it to stop. Dropping the handle does *not* stop the
/// task (standard `tokio::task::JoinHandle` semantics), so hold onto
/// it for the lifetime you want cover traffic active.
pub fn spawn(
    topology: Arc<Topology>,
    hop_count: usize,
    min_interval: Duration,
    max_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let generator = DummyTrafficGenerator::new(min_interval, max_interval);
        let mut rng = OsRng;

        loop {
            let dummy_cell = generator.next_dummy(&mut rng).await;

            let mut throwaway_key = [0u8; 32];
            rng.fill_bytes(&mut throwaway_key);
            let Ok(encrypted) = encrypt_cell(&throwaway_key, &dummy_cell) else {
                continue;
            };

            let mut fake_sender_bytes = [0u8; 32];
            rng.fill_bytes(&mut fake_sender_bytes);
            let enveloped = envelope::wrap(&PublicKey::from(fake_sender_bytes), &encrypted);

            let Ok(path) = select_path(&topology, hop_count, &mut rng) else {
                continue;
            };
            let Ok(onion) = build_circuit(&path, enveloped.to_vec()) else {
                continue;
            };

            if let Ok(mut stream) = TcpStream::connect(&path[0].address).await {
                let _ = write_frame(&mut stream, &onion).await;
            }
        }
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    use veil_core::crypto::KeyPair;
    use veil_relay::config::RelayConfig;
    use veil_relay::node::RelayNode;
    use veil_routing::topology::RelayInfo;

    #[tokio::test]
    async fn cover_traffic_actually_delivers_cells_to_a_relay() {
        let addr: std::net::SocketAddr = "127.0.0.1:23000".parse().unwrap();
        let keypair = KeyPair::generate(&mut OsRng);
        let public_key = keypair.public_key();
        let config = RelayConfig {
            listen_addr: addr,
            relay_id: "cover-relay".to_string(),
            static_secret_hex: None,
            max_connections: 16,
        };
        let (node, mut delivery_rx) = RelayNode::new(config, keypair);
        tokio::spawn(node.run());

        let mut topology = Topology::new();
        topology.add_relay(RelayInfo {
            id: "cover-relay".to_string(),
            address: addr.to_string(),
            public_key,
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Single relay, hop_count = 1: it is deterministically the
        // exit relay, so this test is not flaky by construction.
        let handle = spawn(
            Arc::new(topology),
            1,
            Duration::from_millis(10),
            Duration::from_millis(30),
        );

        let delivered = tokio::time::timeout(Duration::from_secs(3), delivery_rx.recv())
            .await
            .expect("timed out waiting for cover traffic to be delivered")
            .expect("delivery channel closed");

        assert_eq!(
            delivered.len(),
            envelope::ENVELOPE_SIZE,
            "dummy cells must be indistinguishable in size from a real enveloped cell"
        );

        handle.abort();
    }
}
