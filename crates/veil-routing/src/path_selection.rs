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

/// Like [`select_path`], but tries to avoid selecting more than one
/// relay from the same IPv4 /24 subnet — a lightweight mitigation
/// against a single operator running many relays on adjacent
/// addresses to increase their odds of controlling multiple hops in
/// one circuit.
///
/// This is best-effort, not a guarantee. Relay addresses that aren't
/// parseable IPv4 literals (hostnames, IPv6, Docker service names)
/// are treated as having an unknown subnet and are never excluded on
/// diversity grounds alone. If there aren't enough subnet-diverse
/// relays to fill `hop_count` — e.g. a small topology where every
/// relay happens to run on `127.0.0.1`, as in local testing — this
/// falls back to allowing subnet repeats rather than failing. Real
/// path diversity is a property of a healthy, operator-diverse
/// `Topology`; this function can only make the best of whatever
/// topology it is given, not manufacture diversity that isn't there.
pub fn select_diverse_path<'a>(
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

    let mut path: Vec<&RelayInfo> = Vec::with_capacity(hop_count);
    let mut used_subnets: Vec<[u8; 3]> = Vec::new();
    let mut leftover: Vec<&RelayInfo> = Vec::new();

    for relay in candidates {
        match subnet_key(&relay.address) {
            Some(key) if used_subnets.contains(&key) => leftover.push(relay),
            Some(key) => {
                used_subnets.push(key);
                path.push(relay);
            }
            None => path.push(relay),
        }
    }

    // Diversity-constrained pass came up short: fill the remainder
    // from relays we set aside for sharing an already-used subnet,
    // rather than failing outright.
    for relay in leftover {
        if path.len() == hop_count {
            break;
        }
        path.push(relay);
    }

    path.truncate(hop_count);
    Ok(path)
}

/// Extracts the first three octets of a relay address's IPv4 host, if
/// it has one — used as a coarse stand-in for "network operator" when
/// no richer operator metadata is available. Returns `None` for
/// anything that isn't a literal IPv4 address (hostnames, IPv6), so
/// callers must treat that as "diversity unknown", not "diverse".
fn subnet_key(address: &str) -> Option<[u8; 3]> {
    let host = address.rsplit_once(':')?.0;
    let ip: std::net::Ipv4Addr = host.parse().ok()?;
    let [a, b, c, _] = ip.octets();
    Some([a, b, c])
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
        assert!(matches!(
            result,
            Err(PathSelectionError::InsufficientRelays { .. })
        ));
    }

    fn topology_with_addresses(addresses: &[&str]) -> Topology {
        let mut topo = Topology::new();
        for (i, addr) in addresses.iter().enumerate() {
            topo.add_relay(RelayInfo {
                id: format!("relay-{i}"),
                address: addr.to_string(),
                public_key: KeyPair::generate(&mut OsRng).public_key(),
            });
        }
        topo
    }

    #[test]
    fn diverse_path_avoids_repeating_subnets_when_alternatives_exist() {
        // Four distinct /24 subnets, one relay each — a diverse path
        // of 4 must use every subnet exactly once.
        let topo = topology_with_addresses(&[
            "10.0.1.1:9001",
            "10.0.2.1:9001",
            "10.0.3.1:9001",
            "10.0.4.1:9001",
        ]);
        let mut rng = OsRng;
        let path = select_diverse_path(&topo, 4, &mut rng).unwrap();

        let mut subnets: Vec<[u8; 3]> =
            path.iter().filter_map(|r| subnet_key(&r.address)).collect();
        let before = subnets.len();
        subnets.sort_unstable();
        subnets.dedup();
        assert_eq!(
            subnets.len(),
            before,
            "no subnet should appear twice when diverse options exist"
        );
    }

    #[test]
    fn diverse_path_degrades_gracefully_when_topology_has_no_diversity() {
        // Every relay on 127.0.0.1, only distinguished by port — the
        // exact shape of every existing local test/demo topology in
        // this codebase. Must still succeed, not error.
        let topo = topology_with(5);
        let mut rng = OsRng;
        let path = select_diverse_path(&topo, 3, &mut rng).unwrap();
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn diverse_path_prefers_diversity_over_full_repeats_when_partially_available() {
        // Two relays share a subnet, two more are each on their own —
        // a 3-hop diverse path should be able to use three distinct
        // subnets rather than doubling up unnecessarily.
        let topo = topology_with_addresses(&[
            "10.0.1.1:9001",
            "10.0.1.2:9001", // same /24 as the line above
            "10.0.2.1:9001",
            "10.0.3.1:9001",
        ]);
        let mut rng = OsRng;
        let path = select_diverse_path(&topo, 3, &mut rng).unwrap();

        let mut subnets: Vec<[u8; 3]> =
            path.iter().filter_map(|r| subnet_key(&r.address)).collect();
        let before = subnets.len();
        subnets.sort_unstable();
        subnets.dedup();
        assert_eq!(
            subnets.len(),
            before,
            "with enough diverse relays available, none should be wasted on a repeat"
        );
    }

    #[test]
    fn diverse_path_errors_when_topology_too_small() {
        let topo = topology_with(2);
        let mut rng = OsRng;
        let result = select_diverse_path(&topo, 5, &mut rng);
        assert!(matches!(
            result,
            Err(PathSelectionError::InsufficientRelays { .. })
        ));
    }

    #[test]
    fn subnet_key_handles_hostnames_and_ipv6_as_unknown() {
        assert_eq!(
            subnet_key("relay2:9001"),
            None,
            "Docker service names have no IPv4 subnet"
        );
        assert_eq!(
            subnet_key("[::1]:9001"),
            None,
            "IPv6 literals aren't parsed as IPv4"
        );
        assert_eq!(subnet_key("not-even-an-address"), None);
    }

    #[test]
    fn subnet_key_ignores_port_differences_on_the_same_host() {
        assert_eq!(subnet_key("127.0.0.1:9001"), subnet_key("127.0.0.1:9002"));
    }
}
