//! Loading and saving a [`Topology`] as a JSON file.
//!
//! Everything else in this crate assumes a client already has a
//! `Topology` in hand. This module is how it gets one without
//! spawning the relays itself — e.g. a fixed set of relays running in
//! Docker with persistent identities generated via
//! `veil-relay-keygen` (see `docker/config/` and `topology/`).
//!
//! File format (version 1):
//! ```json
//! {
//!   "version": 1,
//!   "relays": [
//!     { "id": "relay-1", "address": "127.0.0.1:9001", "public_key": "<64 hex chars>" }
//!   ]
//! }
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use veil_core::crypto::{public_key_from_bytes, public_key_to_hex};

use crate::topology::{RelayInfo, Topology};

const CURRENT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum TopologyFileError {
    #[error("cannot read topology file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot write topology file {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("malformed topology JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("relay {id:?} has an invalid public_key: {reason}")]
    InvalidPublicKey { id: String, reason: &'static str },
    #[error("unsupported topology file version {found} (this build reads version {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
struct TopologyFile {
    version: u32,
    relays: Vec<RelayEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayEntry {
    id: String,
    address: String,
    public_key: String,
}

impl Topology {
    /// Loads a topology from a JSON file on disk. See the module docs
    /// for the expected format.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Topology, TopologyFileError> {
        let raw =
            std::fs::read_to_string(path.as_ref()).map_err(|source| TopologyFileError::Read {
                path: path.as_ref().display().to_string(),
                source,
            })?;
        Self::from_json(&raw)
    }

    /// Parses a topology from a JSON string directly, without
    /// touching the filesystem — the counterpart callers use for
    /// testing the format in isolation.
    pub fn from_json(raw: &str) -> Result<Topology, TopologyFileError> {
        let file: TopologyFile = serde_json::from_str(raw)?;
        if file.version != CURRENT_VERSION {
            return Err(TopologyFileError::UnsupportedVersion {
                found: file.version,
                expected: CURRENT_VERSION,
            });
        }

        let mut topology = Topology::new();
        for entry in file.relays {
            let bytes = hex::decode(&entry.public_key).map_err(|_| {
                TopologyFileError::InvalidPublicKey {
                    id: entry.id.clone(),
                    reason: "not valid hex",
                }
            })?;
            let array: [u8; 32] =
                bytes
                    .try_into()
                    .map_err(|_| TopologyFileError::InvalidPublicKey {
                        id: entry.id.clone(),
                        reason: "must decode to exactly 32 bytes",
                    })?;

            topology.add_relay(RelayInfo {
                id: entry.id,
                address: entry.address,
                public_key: public_key_from_bytes(array),
            });
        }

        Ok(topology)
    }

    /// Serializes this topology to the JSON format [`Topology::load_from_file`]
    /// reads — the inverse operation, used to publish a freshly
    /// assembled set of relay identities as a topology file.
    pub fn to_json(&self) -> String {
        let file = TopologyFile {
            version: CURRENT_VERSION,
            relays: self
                .all()
                .map(|r| RelayEntry {
                    id: r.id.clone(),
                    address: r.address.clone(),
                    public_key: public_key_to_hex(&r.public_key),
                })
                .collect(),
        };
        serde_json::to_string_pretty(&file).expect("TopologyFile only contains serializable fields")
    }

    /// Writes this topology to `path` as JSON via [`Topology::to_json`].
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), TopologyFileError> {
        std::fs::write(path.as_ref(), self.to_json()).map_err(|source| TopologyFileError::Write {
            path: path.as_ref().display().to_string(),
            source,
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;
    use veil_core::crypto::KeyPair;

    fn sample_topology() -> Topology {
        let mut topo = Topology::new();
        for i in 0..3 {
            topo.add_relay(RelayInfo {
                id: format!("relay-{i}"),
                address: format!("127.0.0.1:{}", 9001 + i),
                public_key: KeyPair::generate(&mut OsRng).public_key(),
            });
        }
        topo
    }

    #[test]
    fn json_roundtrip_preserves_every_relay() {
        let original = sample_topology();
        let json = original.to_json();
        let restored = Topology::from_json(&json).unwrap();

        assert_eq!(restored.len(), original.len());
        for relay in original.all() {
            let restored_relay = restored
                .get(&relay.id)
                .expect("relay id should survive the roundtrip");
            assert_eq!(restored_relay.address, relay.address);
            assert_eq!(
                restored_relay.public_key.as_bytes(),
                relay.public_key.as_bytes()
            );
        }
    }

    #[test]
    fn file_roundtrip_via_a_real_temp_file() {
        let original = sample_topology();
        let path =
            std::env::temp_dir().join(format!("veil-topology-test-{}.json", std::process::id()));

        original.save_to_file(&path).unwrap();
        let restored = Topology::load_from_file(&path).unwrap();

        assert_eq!(restored.len(), original.len());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let json = r#"{"version": 99, "relays": []}"#;
        let result = Topology::from_json(json);
        assert!(matches!(
            result,
            Err(TopologyFileError::UnsupportedVersion { found: 99, .. })
        ));
    }

    #[test]
    fn invalid_hex_public_key_is_rejected() {
        let json = r#"{
            "version": 1,
            "relays": [{ "id": "bad", "address": "127.0.0.1:9001", "public_key": "not hex at all" }]
        }"#;
        let result = Topology::from_json(json);
        assert!(matches!(
            result,
            Err(TopologyFileError::InvalidPublicKey { .. })
        ));
    }

    #[test]
    fn wrong_length_public_key_is_rejected() {
        let json = r#"{
            "version": 1,
            "relays": [{ "id": "bad", "address": "127.0.0.1:9001", "public_key": "aabbcc" }]
        }"#;
        let result = Topology::from_json(json);
        assert!(matches!(
            result,
            Err(TopologyFileError::InvalidPublicKey { .. })
        ));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let result = Topology::from_json("not json at all");
        assert!(matches!(result, Err(TopologyFileError::Parse(_))));
    }
}
