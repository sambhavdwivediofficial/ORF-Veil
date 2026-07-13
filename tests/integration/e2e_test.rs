//! Cross-crate integration tests: exercise `veil-core`, `veil-relay`,
//! `veil-routing`, and `veil-sdk` together over real TCP sockets, the
//! way an actual application would — not any single crate's internal
//! unit tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::sync::mpsc;

use veil_core::crypto::{decrypt_cell, KeyPair, ENCRYPTED_CELL_SIZE};
use veil_relay::config::RelayConfig;
use veil_relay::node::RelayNode;
use veil_routing::topology::{RelayInfo, Topology};
use veil_sdk::{Session, VeilClient};

/// Spins up `count` real relay nodes on localhost starting at
/// `base_port`, and returns the topology plus each relay's delivery
/// channel keyed by relay id.
async fn spin_up_relays(
    base_port: u16,
    count: usize,
) -> (Topology, HashMap<String, mpsc::UnboundedReceiver<Vec<u8>>>) {
    let mut topology = Topology::new();
    let mut deliveries = HashMap::new();

    for i in 0..count {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", base_port + i as u16)
            .parse()
            .unwrap();
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
    (topology, deliveries)
}

#[tokio::test]
async fn message_delivered_correctly_through_three_hop_circuit() {
    let (topology, mut deliveries) = spin_up_relays(21000, 3).await;

    let recipient = KeyPair::generate(&mut OsRng);
    let session = Session::establish(&recipient.public_key()).unwrap();

    let client = VeilClient::new(topology, 3);
    let sent = client
        .send(&session, b"integration test payload")
        .await
        .unwrap();
    assert_eq!(sent.len(), 1, "short message should fit in a single cell");

    let exit_rx = deliveries.get_mut(&sent[0].exit_relay_id).unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(3), exit_rx.recv())
        .await
        .expect("delivery timed out")
        .expect("delivery channel closed");

    let encrypted: [u8; ENCRYPTED_CELL_SIZE] = delivered.try_into().unwrap();
    let shared = recipient.diffie_hellman(&session.public_key());
    let key = shared.derive_key(b"veil-sdk-session-v1").unwrap();
    let cell = decrypt_cell(&key, &encrypted).unwrap();

    assert_eq!(cell.payload(), b"integration test payload");
}

#[tokio::test]
async fn wrong_recipient_key_cannot_read_the_delivered_cell() {
    let (topology, mut deliveries) = spin_up_relays(21100, 3).await;

    let real_recipient = KeyPair::generate(&mut OsRng);
    let attacker = KeyPair::generate(&mut OsRng);
    let session = Session::establish(&real_recipient.public_key()).unwrap();

    let client = VeilClient::new(topology, 3);
    let sent = client
        .send(&session, b"only the real recipient should read this")
        .await
        .unwrap();

    let exit_rx = deliveries.get_mut(&sent[0].exit_relay_id).unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(3), exit_rx.recv())
        .await
        .expect("delivery timed out")
        .expect("delivery channel closed");
    let encrypted: [u8; ENCRYPTED_CELL_SIZE] = delivered.try_into().unwrap();

    // The attacker knows the sender's ephemeral public key (it travels
    // with the cell, as any handshake key would) but not the real
    // recipient's private key, so their derived key must differ.
    let attacker_shared = attacker.diffie_hellman(&session.public_key());
    let attacker_key = attacker_shared.derive_key(b"veil-sdk-session-v1").unwrap();

    assert!(decrypt_cell(&attacker_key, &encrypted).is_err());
}

#[tokio::test]
async fn concurrent_sends_all_arrive_intact() {
    let (topology, mut deliveries) = spin_up_relays(21200, 3).await;

    let recipient = KeyPair::generate(&mut OsRng);
    let session = Arc::new(Session::establish(&recipient.public_key()).unwrap());
    let client = Arc::new(VeilClient::new(topology, 3));

    let messages = [
        "first concurrent message",
        "second concurrent message",
        "third concurrent message",
    ];

    let mut handles = Vec::new();
    for msg in messages {
        let client = client.clone();
        let session = session.clone();
        handles.push(tokio::spawn(async move {
            client.send(&session, msg.as_bytes()).await.unwrap()
        }));
    }

    let mut exit_ids = Vec::new();
    for handle in handles {
        exit_ids.push(handle.await.unwrap()[0].exit_relay_id.clone());
    }

    let shared = recipient.diffie_hellman(&session.public_key());
    let key = shared.derive_key(b"veil-sdk-session-v1").unwrap();

    let mut received = Vec::new();
    for exit_id in &exit_ids {
        let rx = deliveries.get_mut(exit_id).unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("delivery timed out")
            .expect("delivery channel closed");
        let encrypted: [u8; ENCRYPTED_CELL_SIZE] = delivered.try_into().unwrap();
        let cell = decrypt_cell(&key, &encrypted).unwrap();
        received.push(String::from_utf8_lossy(cell.payload()).to_string());
    }

    for msg in messages {
        assert!(
            received.iter().any(|r| r == msg),
            "message {msg:?} was not delivered"
        );
    }
}
