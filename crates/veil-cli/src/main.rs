//! Local demonstration harness.
//!
//! Spins up N in-process relay nodes, builds a real multi-hop circuit
//! through them via `veil-sdk`, and sends a message end to end —
//! proving the full stack (core + relay + routing + sdk) works
//! together without needing separately running relay processes or a
//! standalone receiver client.
//!
//! Usage: `cargo run -p veil-cli -- "your message" [hop_count]`

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::sync::mpsc;

use veil_core::crypto::{decrypt_cell, KeyPair, ENCRYPTED_CELL_SIZE};
use veil_relay::config::RelayConfig;
use veil_relay::node::RelayNode;
use veil_routing::topology::{RelayInfo, Topology};
use veil_sdk::{Session, VeilClient};

#[tokio::main]
async fn main() {
    let message = env::args()
        .nth(1)
        .unwrap_or_else(|| "hello from veil-cli".to_string());
    let hop_count: usize = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    println!("veil-cli: spinning up {hop_count} local relay(s) for a demo circuit");

    let mut topology = Topology::new();
    let mut deliveries: HashMap<String, mpsc::UnboundedReceiver<Vec<u8>>> = HashMap::new();

    for i in 0..hop_count {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", 20000 + i).parse().unwrap();
        let relay_id = format!("relay-{i}");

        let keypair = KeyPair::generate(&mut OsRng);
        let public_key = keypair.public_key();

        let config = RelayConfig {
            listen_addr: addr,
            relay_id: relay_id.clone(),
            static_secret_hex: None,
            max_connections: 16,
        };
        let (node, delivery_rx) = RelayNode::new(config, keypair);
        tokio::spawn(node.run());

        deliveries.insert(relay_id.clone(), delivery_rx);
        topology.add_relay(RelayInfo {
            id: relay_id,
            address: addr.to_string(),
            public_key,
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The CLI plays both sender and recipient here purely for the
    // demo — a real recipient would hold this identity keypair
    // privately on their own machine.
    let recipient_identity = KeyPair::generate(&mut OsRng);
    let session =
        Session::establish(&recipient_identity.public_key()).expect("session setup failed");

    let client = VeilClient::new(topology, hop_count);
    let sent = client
        .send(&session, message.as_bytes())
        .await
        .expect("send failed");

    println!(
        "veil-cli: sent as {} cell(s) through {hop_count}-hop circuit(s)",
        sent.len()
    );
    if sent.len() > 1 {
        println!("veil-cli: demo listens on the first cell's exit relay only — later fragments took independent paths by design");
    }

    let exit_id = &sent[0].exit_relay_id;
    let mut exit_delivery = deliveries
        .remove(exit_id)
        .expect("exit relay must exist in topology");

    let delivered = tokio::time::timeout(Duration::from_secs(3), exit_delivery.recv())
        .await
        .expect("timed out waiting for delivery")
        .expect("delivery channel closed");

    // The exit relay only ever saw this encrypted cell. Decrypting it
    // here simulates what the recipient application does after
    // receiving it over its own connection to the exit relay.
    let encrypted: [u8; ENCRYPTED_CELL_SIZE] = delivered
        .try_into()
        .expect("delivered cell had an unexpected size");
    let recipient_shared = recipient_identity.diffie_hellman(&session.public_key());
    let recipient_key = recipient_shared
        .derive_key(b"veil-sdk-session-v1")
        .expect("key derivation failed");
    let cell = decrypt_cell(&recipient_key, &encrypted).expect("decrypt failed");

    println!(
        "veil-cli: delivered payload = {:?}",
        String::from_utf8_lossy(cell.payload())
    );
}
