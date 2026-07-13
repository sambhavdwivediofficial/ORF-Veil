//! Random circuit path selection.
//!
//! A fresh path should be drawn per cell, not reused across a whole
//! message — reusing one path for every fragment of a message would
//! let a single compromised relay link all of that message's cells
//! together, defeating the point of independent per-cell routing.

use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::topology::{RelayInfo, Topology};

#[derive(Debug, Error)]
pub enum PathSelectionError {
    #[error("not enough relays in topology: need {needed}, have {available}")]
    InsufficientRelays { needed: usize, available: usize },
}

/// Selects `hop_count` distinct relays from `topology` in random order,
/// forming an ordered circuit path: `path[0]` is the entry hop,
/// `path[last]` is the exit hop.
pub fn select_path<'a>(
    topology: &'a Topology,
    hop_count: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<&'a RelayInfo>, PathSelectionError> {
    let mut candidates: Vec<&RelayInfo> = topology.all().collect();
    if candidates.len() < hop_count {
        return Err(PathSelectionError::InsufficientRelays {
            needed: hop_count,
            available: candidates.len(),
        });
    }

    candidates.shuffle(rng);
    Ok(candidates.into_iter().take(hop_count).collect())
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;
    use veil_core::crypto::KeyPair;

    fn topology_with(n: usize) -> Topology {
        let mut topo = Topology::new();
        for i in 0..n {
            topo.add_relay(RelayInfo {
                id: format!("relay-{i}"),
                address: format!("127.0.0.1:{}", 9000 + i),
                public_key: KeyPair::generate(&mut OsRng).public_key(),
            });
        }
        topo
    }

    #[test]
    fn selects_requested_hop_count() {
        let topo = topology_with(5);
        let mut rng = OsRng;
        let path = select_path(&topo, 3, &mut rng).unwrap();
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn selected_relays_are_distinct() {
        let topo = topology_with(5);
        let mut rng = OsRng;
        let path = select_path(&topo, 4, &mut rng).unwrap();
        let mut ids: Vec<&str> = path.iter().map(|r| r.id.as_str()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "path must not repeat a relay");
    }

    #[test]
    fn errors_when_topology_too_small() {
        let topo = topology_with(2);
        let mut rng = OsRng;
        let result = select_path(&topo, 5, &mut rng);
        assert!(matches!(result, Err(PathSelectionError::InsufficientRelays { .. })));
    }
}
