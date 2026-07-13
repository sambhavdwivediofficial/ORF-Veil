//! Manual end-to-end smoke test: spins up two real relay nodes on
//! localhost, builds a 2-hop onion circuit exactly as a future
//! client/SDK would, sends it over a real TCP socket, and confirms
//! the exit relay actually delivers the innermost cell.
use std::time::Duration;

use rand::rngs::OsRng;
use veil_core::crypto::KeyPair;
use veil_relay::config::RelayConfig;
use veil_relay::forwarding::{build_onion_layer, write_frame, OnionPayload};
use veil_relay::node::RelayNode;

#[tokio::main]
async fn main() {
    // --- Relay 2 (exit node) ---
    let relay2_config = RelayConfig {
        listen_addr: "127.0.0.1:19002".parse().unwrap(),
        relay_id: "relay-2".into(),
        static_secret_hex: None,
        max_connections: 16,
    };
    let relay2_keypair = KeyPair::generate(&mut OsRng);
    let relay2_pubkey = relay2_keypair.public_key();
    let (relay2_node, mut relay2_delivery) = RelayNode::new(relay2_config, relay2_keypair);
    tokio::spawn(relay2_node.run());

    // --- Relay 1 (entry node) ---
    let relay1_config = RelayConfig {
        listen_addr: "127.0.0.1:19001".parse().unwrap(),
        relay_id: "relay-1".into(),
        static_secret_hex: None,
        max_connections: 16,
    };
    let relay1_keypair = KeyPair::generate(&mut OsRng);
    let relay1_pubkey = relay1_keypair.public_key();
    let (relay1_node, _relay1_delivery) = RelayNode::new(relay1_config, relay1_keypair);
    tokio::spawn(relay1_node.run());

    tokio::time::sleep(Duration::from_millis(200)).await;

    // --- Client builds a 2-hop onion, innermost layer first ---
    let final_cell = b"this is the real message payload".to_vec();
    let layer_for_relay2 = build_onion_layer(
        &relay2_pubkey,
        &OnionPayload::Deliver {
            body: final_cell.clone(),
        },
    )
    .unwrap();

    let layer_for_relay1 = build_onion_layer(
        &relay1_pubkey,
        &OnionPayload::Forward {
            next_hop: "127.0.0.1:19002".into(),
            body: layer_for_relay2,
        },
    )
    .unwrap();

    // Client sends the outermost layer to relay 1 only.
    let mut client_stream = tokio::net::TcpStream::connect("127.0.0.1:19001")
        .await
        .unwrap();
    write_frame(&mut client_stream, &layer_for_relay1)
        .await
        .unwrap();

    // Relay 1 should peel its layer, see "forward to relay 2", and
    // relay 1 never sees final_cell in plaintext — relay 2 does, and
    // only relay 2, after peeling its own layer.
    let delivered = tokio::time::timeout(Duration::from_secs(3), relay2_delivery.recv())
        .await
        .expect("timed out waiting for delivery")
        .expect("delivery channel closed");

    assert_eq!(delivered, final_cell);
    println!(
        "SUCCESS: cell traveled client -> relay-1 -> relay-2 -> delivered, exactly as designed"
    );
}
