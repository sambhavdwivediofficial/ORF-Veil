//! The set of relays a client knows about and may route through.

use std::collections::HashMap;

use x25519_dalek::PublicKey;

#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub id: String,
    pub address: String,
    pub public_key: PublicKey,
}

#[derive(Default)]
pub struct Topology {
    relays: HashMap<String, RelayInfo>,
}

impl Topology {
    pub fn new() -> Self {
        Self { relays: HashMap::new() }
    }

    pub fn add_relay(&mut self, relay: RelayInfo) {
        self.relays.insert(relay.id.clone(), relay);
    }

    pub fn get(&self, id: &str) -> Option<&RelayInfo> {
        self.relays.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &RelayInfo> {
        self.relays.values()
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;
    use veil_core::crypto::KeyPair;

    fn dummy_relay(id: &str) -> RelayInfo {
        RelayInfo {
            id: id.to_string(),
            address: format!("127.0.0.1:{}", 9000),
            public_key: KeyPair::generate(&mut OsRng).public_key(),
        }
    }

    #[test]
    fn add_and_get_relay() {
        let mut topo = Topology::new();
        topo.add_relay(dummy_relay("r1"));
        assert!(topo.get("r1").is_some());
        assert!(topo.get("nonexistent").is_none());
    }

    #[test]
    fn len_reflects_relay_count() {
        let mut topo = Topology::new();
        assert!(topo.is_empty());
        topo.add_relay(dummy_relay("r1"));
        topo.add_relay(dummy_relay("r2"));
        assert_eq!(topo.len(), 2);
    }
}
