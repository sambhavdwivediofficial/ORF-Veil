//! Relay configuration, loaded from a TOML file.

use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

use crate::node::RelayError;

#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub relay_id: String,
    /// Hex-encoded persisted identity key. Left unset in the default
    /// config, in which case a fresh ephemeral identity is generated
    /// at startup — fine for local testing, not for a long-running
    /// relay peers need to keep addressing consistently.
    #[serde(default)]
    pub static_secret_hex: Option<String>,
    /// Reserved for a future connection-limiting pass; not yet
    /// enforced by [`crate::node::RelayNode`].
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_max_connections() -> usize {
    256
}

impl RelayConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RelayError> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            RelayError::Config(format!("cannot read {}: {e}", path.as_ref().display()))
        })?;
        toml::from_str(&raw).map_err(|e| RelayError::Config(format!("invalid config: {e}")))
    }
}
