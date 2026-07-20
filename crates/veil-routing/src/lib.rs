//! Circuit construction: combines [`path_selection`] with the
//! onion-layer primitives in `veil-relay` to produce a fully wrapped
//! packet ready to hand to the first hop.

pub mod discovery;
pub mod dummy_traffic;
pub mod path_selection;
pub mod topology;
pub mod topology_file;

use thiserror::Error;

use veil_relay::forwarding::{build_onion_layer, OnionError, OnionPayload};

use crate::topology::RelayInfo;

pub use topology_file::TopologyFileError;

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("path selection failed: {0}")]
    PathSelection(#[from] path_selection::PathSelectionError),
    #[error("onion layer construction failed: {0}")]
    Onion(#[from] OnionError),
    #[error("path must contain at least one relay")]
    EmptyPath,
}

/// Wraps `final_body` in nested onion layers for `path`, innermost
/// (exit relay) first, so that only the last relay in `path` ever sees
/// `final_body`, and each relay learns only the address of the very
/// next hop. The returned bytes should be sent to `path[0]`'s address.
pub fn build_circuit(path: &[&RelayInfo], final_body: Vec<u8>) -> Result<Vec<u8>, CircuitError> {
    let (exit, inner_hops) = path.split_last().ok_or(CircuitError::EmptyPath)?;

    let mut layer = build_onion_layer(
        &exit.public_key,
        &OnionPayload::Deliver { body: final_body },
    )?;

    for i in (0..inner_hops.len()).rev() {
        let hop = inner_hops[i];
        let next_hop_addr = if i + 1 < inner_hops.len() {
            inner_hops[i + 1].address.clone()
        } else {
            exit.address.clone()
        };
        layer = build_onion_layer(
            &hop.public_key,
            &OnionPayload::Forward {
                next_hop: next_hop_addr,
                body: layer,
            },
        )?;
    }

    Ok(layer)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;
    use veil_core::crypto::KeyPair;
    use veil_relay::forwarding::peel_onion_layer;

    struct TestRelay {
        info: RelayInfo,
        keypair: KeyPair,
    }

    fn make_relay(id: &str, port: u16) -> TestRelay {
        let keypair = KeyPair::generate(&mut OsRng);
        let info = RelayInfo {
            id: id.to_string(),
            address: format!("127.0.0.1:{port}"),
            public_key: keypair.public_key(),
        };
        TestRelay { info, keypair }
    }

    #[test]
    fn three_hop_circuit_peels_correctly_at_every_hop() {
        let r1 = make_relay("r1", 9001);
        let r2 = make_relay("r2", 9002);
        let r3 = make_relay("r3", 9003);
        let path = [&r1.info, &r2.info, &r3.info];

        let onion = build_circuit(&path, b"final message".to_vec()).unwrap();

        // Relay 1 peels its layer: should reveal "forward to r2".
        let peeled_1 = peel_onion_layer(&r1.keypair, &onion).unwrap();
        let layer_for_r2 = match peeled_1 {
            OnionPayload::Forward { next_hop, body } => {
                assert_eq!(next_hop, r2.info.address);
                body
            }
            _ => panic!("relay 1 should forward"),
        };

        // Relay 2 peels its layer: should reveal "forward to r3".
        let peeled_2 = peel_onion_layer(&r2.keypair, &layer_for_r2).unwrap();
        let layer_for_r3 = match peeled_2 {
            OnionPayload::Forward { next_hop, body } => {
                assert_eq!(next_hop, r3.info.address);
                body
            }
            _ => panic!("relay 2 should forward"),
        };

        // Relay 3 (exit) peels its layer: should reveal the final body.
        let peeled_3 = peel_onion_layer(&r3.keypair, &layer_for_r3).unwrap();
        match peeled_3 {
            OnionPayload::Deliver { body } => assert_eq!(body, b"final message"),
            _ => panic!("relay 3 should deliver"),
        }
    }

    #[test]
    fn empty_path_is_rejected() {
        let path: [&RelayInfo; 0] = [];
        let result = build_circuit(&path, b"x".to_vec());
        assert!(matches!(result, Err(CircuitError::EmptyPath)));
    }
}
