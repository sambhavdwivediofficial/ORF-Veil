//! Local demonstration harness.
//!
//! Spins up N in-process relay nodes (each with its own mailbox pull
//! listener), sends a message through a real multi-hop circuit via
//! `veil-sdk`, and then *receives* it back the same way a genuinely
//! separate recipient process would: by polling every relay's mailbox
//! over a real TCP connection and decrypting whatever comes back —
//! not by peeking at in-process state.
//!
//! Usage: `cargo run -p veil-cli -- "your message" [hop_count]`

use std::env;
use std::time::Duration;

use rand::rngs::OsRng;

use veil_core::crypto::KeyPair;
use veil_relay::config::RelayConfig;
use veil_relay::mailbox::Mailbox;
use veil_relay::node::RelayNode;
use veil_relay::pull_listener;
use veil_routing::topology::{RelayInfo, Topology};
use veil_sdk::{receiver, Session, VeilClient};

#[tokio::main]
async fn main() {
    let message = env::args()
        .nth(1)
        .unwrap_or_else(|| "hello from veil-cli".to_string());
    let hop_count: usize = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    println!(
        "veil-cli: spinning up {hop_count} local relay(s), each with its own mailbox listener"
    );

    let mut topology = Topology::new();
    let mut mailbox_addrs: Vec<String> = Vec::new();

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
        let (node, mut delivery_rx) = RelayNode::new(config, keypair);
        tokio::spawn(node.run());

        // Same convention veil-relay's binary uses: mailbox listener
        // runs on listen_addr's port + 1000.
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

    // The CLI plays both sender and recipient here purely for the
    // demo — a real recipient would generate and keep this identity
    // keypair privately on their own machine, and would never see
    // `session` at all.
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
        println!("veil-cli: fragments took independent paths by design — receive polls every relay, so this is still fine");
    }

    // Give the exit relay(s) a moment to actually process the delivery
    // before the receiving side polls.
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!(
        "veil-cli: receiving — polling {} relay mailbox(es) over the network",
        mailbox_addrs.len()
    );
    let received = receiver::receive(&recipient_identity, &mailbox_addrs)
        .await
        .expect("receive failed");

    if received.is_empty() {
        eprintln!("veil-cli: nothing decrypted — the cell may not have arrived yet, or something is wrong");
        std::process::exit(1);
    }

    for cell in &received {
        println!(
            "veil-cli: delivered payload = {:?}",
            String::from_utf8_lossy(cell.payload())
        );
    }
}
