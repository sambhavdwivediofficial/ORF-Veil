//! Topology discovery: build a [`Topology`] from nothing but a list of
//! relay mailbox addresses, by asking each relay to describe itself
//! (see `veil_relay::pull_listener::describe`) instead of requiring
//! its id and public key to already be known and written into a
//! topology file (contrast with `topology_file.rs`).

use veil_relay::pull_listener;

use crate::topology::{RelayInfo, Topology};

/// One relay that could not be reached or did not respond correctly
/// during discovery. Collected rather than aborting the whole scan,
/// since a subset of unreachable relays shouldn't prevent building a
/// topology from the ones that did respond.
#[derive(Debug)]
pub struct UnreachableRelay {
    pub address: String,
    pub error: std::io::Error,
}

/// Queries every mailbox address in `addresses` for its own identity
/// and assembles a [`Topology`] from whatever responds successfully.
///
/// `addresses` are relay *mailbox* addresses (main port + 1000,
/// matching `veil-relay`'s convention) — the same addresses a
/// receiving client already polls for deliveries. Each relay reports
/// its own main address back in the DESCRIBE response, so the
/// resulting `Topology` correctly points at main ports, not mailbox
/// ports.
pub async fn discover_topology(addresses: &[String]) -> (Topology, Vec<UnreachableRelay>) {
    let mut topology = Topology::new();
    let mut unreachable = Vec::new();

    for address in addresses {
        match pull_listener::describe(address).await {
            Ok(identity) => {
                topology.add_relay(RelayInfo {
                    id: identity.id,
                    address: identity.main_addr,
                    public_key: identity.public_key,
                });
            }
            Err(error) => unreachable.push(UnreachableRelay {
                address: address.clone(),
                error,
            }),
        }
    }

    (topology, unreachable)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    use rand::rngs::OsRng;
    use veil_core::crypto::KeyPair;
    use veil_relay::config::RelayConfig;
    use veil_relay::mailbox::Mailbox;
    use veil_relay::node::RelayNode;
    use veil_relay::pull_listener::RelayIdentity;

    async fn spin_up_discoverable_relay(port: u16, relay_id: &str) {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let keypair = KeyPair::generate(&mut OsRng);
        let public_key = keypair.public_key();

        let config = RelayConfig {
            listen_addr: addr,
            relay_id: relay_id.to_string(),
            static_secret_hex: None,
            max_connections: 16,
        };
        let (node, _delivery_rx) = RelayNode::new(config, keypair);
        tokio::spawn(node.run());

        let mut mailbox_addr = addr;
        mailbox_addr.set_port(mailbox_addr.port() + 1000);
        let identity = RelayIdentity {
            id: relay_id.to_string(),
            public_key,
            main_addr: addr.to_string(),
        };
        tokio::spawn(async move {
            let _ = veil_relay::pull_listener::serve(mailbox_addr, Mailbox::new(), identity).await;
        });
    }

    #[tokio::test]
    async fn discovers_every_reachable_relay() {
        spin_up_discoverable_relay(25000, "disco-1").await;
        spin_up_discoverable_relay(25001, "disco-2").await;
        spin_up_discoverable_relay(25002, "disco-3").await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let addresses = vec![
            "127.0.0.1:26000".to_string(),
            "127.0.0.1:26001".to_string(),
            "127.0.0.1:26002".to_string(),
        ];
        let (topology, unreachable) = discover_topology(&addresses).await;

        assert_eq!(topology.len(), 3);
        assert!(unreachable.is_empty());
        assert!(topology.get("disco-1").is_some());
        assert_eq!(topology.get("disco-1").unwrap().address, "127.0.0.1:25000");
    }

    #[tokio::test]
    async fn unreachable_relays_are_reported_not_fatal() {
        spin_up_discoverable_relay(25100, "reachable").await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let addresses = vec![
            "127.0.0.1:26100".to_string(),
            "127.0.0.1:26999".to_string(), // nothing listens here
        ];
        let (topology, unreachable) = discover_topology(&addresses).await;

        assert_eq!(topology.len(), 1);
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0].address, "127.0.0.1:26999");
    }
}
