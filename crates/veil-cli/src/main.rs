//! Local command-line demonstration harness.
//!
//! Two modes:
//!
//! **Self-hosted** (default): spins up N in-process relay nodes, each
//! with its own mailbox pull listener, and sends/receives a message
//! through them — proving the full stack works together in one
//! self-contained run.
//!   `cargo run -p veil-cli -- "your message" [hop_count]`
//!
//! **External topology**: loads a set of already-running relays (for
//! example the Docker network in `docker/docker-compose.yml`,
//! described by `topology/local-docker.json`) and routes a real
//! message through them instead of spawning anything locally.
//!   `cargo run -p veil-cli -- "your message" --topology <path>`

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

enum Mode {
    SelfHosted {
        message: String,
        hop_count: usize,
    },
    External {
        topology_path: String,
        message: String,
    },
}

fn parse_args() -> Mode {
    let args: Vec<String> = env::args().skip(1).collect();

    if let Some(flag_pos) = args.iter().position(|a| a == "--topology") {
        let topology_path = args
            .get(flag_pos + 1)
            .cloned()
            .expect("--topology requires a file path, e.g. --topology topology/local-docker.json");

        let message = args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != flag_pos && *i != flag_pos + 1)
            .map(|(_, a)| a.clone())
            .next()
            .unwrap_or_else(|| "hello from veil-cli".to_string());

        Mode::External {
            topology_path,
            message,
        }
    } else {
        let message = args
            .first()
            .cloned()
            .unwrap_or_else(|| "hello from veil-cli".to_string());
        let hop_count = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
        Mode::SelfHosted { message, hop_count }
    }
}

#[tokio::main]
async fn main() {
    match parse_args() {
        Mode::SelfHosted { message, hop_count } => run_self_hosted(message, hop_count).await,
        Mode::External {
            topology_path,
            message,
        } => run_external(topology_path, message).await,
    }
}

/// Spins up local relays, sends a message through them, and receives
/// it back — no external dependencies, works out of the box.
async fn run_self_hosted(message: String, hop_count: usize) {
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

    send_and_receive(topology, hop_count, message, mailbox_addrs).await;
}

/// Loads an externally-running relay fabric from a topology file
/// (e.g. the Docker network) and routes a real message through it —
/// nothing is spawned locally except this client's own identity.
async fn run_external(topology_path: String, message: String) {
    println!("veil-cli: loading external topology from {topology_path}");
    let topology = Topology::load_from_file(&topology_path)
        .unwrap_or_else(|e| panic!("failed to load topology file {topology_path}: {e}"));

    let hop_count = topology.len().clamp(1, 3);
    println!(
        "veil-cli: loaded {} relay(s); routing through {hop_count}-hop circuits",
        topology.len()
    );

    // Mailbox addresses (port + 1000, matching veil-relay's binary
    // convention) must be collected before `topology` moves into
    // VeilClient below.
    let mailbox_addrs: Vec<String> = topology
        .all()
        .map(|r| {
            let mut addr: std::net::SocketAddr = r.address.parse().unwrap_or_else(|_| {
                panic!("invalid relay address in topology file: {}", r.address)
            });
            addr.set_port(addr.port() + 1000);
            addr.to_string()
        })
        .collect();

    send_and_receive(topology, hop_count, message, mailbox_addrs).await;
}

/// Shared send/receive flow for both modes above: establishes a
/// throwaway recipient identity, sends the message, then receives it
/// back purely by polling relay mailboxes over the network — the same
/// way a genuinely separate recipient process would.
async fn send_and_receive(
    topology: Topology,
    hop_count: usize,
    message: String,
    mailbox_addrs: Vec<String>,
) {
    let recipient_identity = KeyPair::generate(&mut OsRng);
    let session =
        Session::establish(&recipient_identity.public_key()).expect("session setup failed");

    let client = VeilClient::new(topology, hop_count);
    let sent = client
        .send(&session, message.as_bytes())
        .await
        .expect("send failed — is the relay fabric reachable?");

    println!(
        "veil-cli: sent as {} cell(s) through {hop_count}-hop circuit(s)",
        sent.len()
    );
    if sent.len() > 1 {
        println!("veil-cli: fragments took independent paths by design — receive polls every relay, so this is still fine");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    println!(
        "veil-cli: receiving — polling {} relay mailbox(es) over the network",
        mailbox_addrs.len()
    );
    let received = receiver::receive(&recipient_identity, &mailbox_addrs)
        .await
        .expect("receive failed");

    if received.is_empty() {
        eprintln!("veil-cli: nothing decrypted — the cell may not have arrived yet, or the fabric is unreachable");
        std::process::exit(1);
    }

    for cell in &received {
        println!(
            "veil-cli: delivered payload = {:?}",
            String::from_utf8_lossy(cell.payload())
        );
    }
}
