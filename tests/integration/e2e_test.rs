//! Cross-crate integration tests: exercise `veil-core`, `veil-relay`,
//! `veil-routing`, and `veil-sdk` together over real TCP sockets, the
//! way an actual application would — not any single crate's internal
//! unit tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::sync::mpsc;

use veil_core::crypto::{decrypt_cell, KeyPair};
use veil_relay::config::RelayConfig;
use veil_relay::mailbox::Mailbox;
use veil_relay::node::RelayNode;
use veil_relay::pull_listener;
use veil_routing::topology::{RelayInfo, Topology};
use veil_sdk::{envelope, receiver, Session, VeilClient};

/// Spins up `count` real relay nodes on localhost starting at
/// `base_port`, and returns the topology plus each relay's delivery
/// channel keyed by relay id. Used by tests that read delivery
/// in-process (the way `veil-cli` originally did).
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

/// Spins up `count` relays exactly like `spin_up_relays`, but also
/// runs each one's mailbox pull listener (port + 1000, matching
/// `veil-relay`'s binary convention) and bridges its delivery channel
/// into that mailbox — the same wiring the real `veil-relay` binary
/// does. Returns only the `Topology`; callers that want to receive
/// use `veil_sdk::receiver::receive` against the mailbox addresses,
/// exactly as a real, separate recipient process would.
async fn spin_up_relays_with_mailboxes(base_port: u16, count: usize) -> (Topology, Vec<String>) {
    let mut topology = Topology::new();
    let mut mailbox_addrs = Vec::new();

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
        let (node, mut delivery_rx) = RelayNode::new(config, keypair);
        tokio::spawn(node.run());

        let mut mailbox_addr = addr;
        mailbox_addr.set_port(mailbox_addr.port() + 1000);
        mailbox_addrs.push(mailbox_addr.to_string());

        let mailbox = Mailbox::new();
        let listener_mailbox = mailbox.clone();
        tokio::spawn(async move {
            let _ = pull_listener::serve(mailbox_addr, listener_mailbox).await;
        });
        tokio::spawn(async move {
            while let Some(delivered) = delivery_rx.recv().await {
                mailbox.push(delivered).await;
            }
        });

        topology.add_relay(RelayInfo {
            id: relay_id,
            address: addr.to_string(),
            public_key,
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    (topology, mailbox_addrs)
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

    let (sender_public, encrypted) = envelope::unwrap(&delivered).unwrap();
    let shared = recipient.diffie_hellman(&sender_public);
    let key = shared.derive_key(b"veil-sdk-session-v1").unwrap();
    let cell = decrypt_cell(&key, &encrypted).unwrap();

    assert_eq!(cell.payload(), b"integration test payload");
    assert_eq!(sender_public.as_bytes(), session.public_key().as_bytes());
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
    let (sender_public, encrypted) = envelope::unwrap(&delivered).unwrap();

    // The attacker can read the sender's ephemeral public key straight
    // off the wire (it is not secret — that is the whole point of the
    // envelope), but not the real recipient's private key, so their
    // derived key must differ.
    let attacker_shared = attacker.diffie_hellman(&sender_public);
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

    let mut received = Vec::new();
    for exit_id in &exit_ids {
        let rx = deliveries.get_mut(exit_id).unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("delivery timed out")
            .expect("delivery channel closed");

        let (sender_public, encrypted) = envelope::unwrap(&delivered).unwrap();
        let shared = recipient.diffie_hellman(&sender_public);
        let key = shared.derive_key(b"veil-sdk-session-v1").unwrap();
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

#[tokio::test]
async fn recipient_receives_by_polling_relay_mailboxes_over_the_network() {
    let (topology, mailbox_addrs) = spin_up_relays_with_mailboxes(21300, 3).await;

    let recipient = KeyPair::generate(&mut OsRng);
    let session = Session::establish(&recipient.public_key()).unwrap();

    let client = VeilClient::new(topology, 3);
    client
        .send(&session, b"delivered via real mailbox pull")
        .await
        .unwrap();

    // A real recipient does not know in advance which relay a given
    // message exited through (path selection is random and chosen by
    // the sender) — so it polls every relay it knows about and keeps
    // whatever successfully decrypts. No in-process shortcut is used
    // here: `receiver::receive` only talks to the relays over TCP.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let received = receiver::receive(&recipient, &mailbox_addrs).await.unwrap();

    assert_eq!(
        received.len(),
        1,
        "exactly one relay's mailbox should have had the cell"
    );
    assert_eq!(received[0].payload(), b"delivered via real mailbox pull");
}

#[tokio::test]
async fn a_different_identity_receives_nothing() {
    let (topology, mailbox_addrs) = spin_up_relays_with_mailboxes(21400, 3).await;

    let real_recipient = KeyPair::generate(&mut OsRng);
    let session = Session::establish(&real_recipient.public_key()).unwrap();

    let client = VeilClient::new(topology, 3);
    client
        .send(&session, b"not for the eavesdropper")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // A different identity polling the exact same mailboxes gets the
    // ciphertext handed to it too (mailboxes are unauthenticated by
    // design — see mailbox.rs) but cannot decrypt any of it.
    let eavesdropper = KeyPair::generate(&mut OsRng);
    let received = receiver::receive(&eavesdropper, &mailbox_addrs)
        .await
        .unwrap();

    assert!(
        received.is_empty(),
        "an identity the message wasn't addressed to should decrypt nothing"
    );
}
