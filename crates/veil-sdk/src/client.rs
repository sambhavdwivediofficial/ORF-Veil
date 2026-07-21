//! High-level client API tying together fragmentation, encryption,
//! path selection, and circuit construction into a single `send` call.

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use veil_core::crypto::encrypt_cell;
use veil_core::fragment_message;
use veil_relay::forwarding::write_frame;
use veil_routing::path_selection::select_diverse_path;
use veil_routing::topology::Topology;
use veil_routing::{build_circuit, CircuitError};

use crate::cover_traffic;
use crate::envelope;
use crate::session::Session;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("cell/fragmentation error: {0}")]
    Core(#[from] veil_core::VeilError),
    #[error("routing error: {0}")]
    Routing(#[from] CircuitError),
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),
}

/// The exit relay a particular cell was routed through — reported back
/// so a caller can, for testing or telemetry, correlate a send with
/// where it should surface on the network.
pub struct SentCircuit {
    pub exit_relay_id: String,
}

pub struct VeilClient {
    topology: Arc<Topology>,
    hop_count: usize,
}

impl VeilClient {
    pub fn new(topology: Topology, hop_count: usize) -> Self {
        Self {
            topology: Arc::new(topology),
            hop_count,
        }
    }

    /// Fragments `message` into cells, encrypts each cell end-to-end
    /// under `session`'s key, wraps each in an envelope carrying the
    /// sender's ephemeral public key (so a genuinely separate
    /// recipient process can later derive the same key — see
    /// `envelope.rs`), and routes every cell independently through a
    /// freshly chosen path — so no single relay, and no external
    /// observer, can link the fragments of one message back together
    /// by path alone.
    pub async fn send(
        &self,
        session: &Session,
        message: &[u8],
    ) -> Result<Vec<SentCircuit>, ClientError> {
        let mut rng = OsRng;
        let cells = fragment_message(message, &mut rng)?;
        let mut sent = Vec::with_capacity(cells.len());

        for cell in cells {
            let encrypted = encrypt_cell(&session.cell_key, &cell)?;
            let enveloped = envelope::wrap(&session.public_key(), &encrypted);

            let path = select_diverse_path(&self.topology, self.hop_count, &mut rng)
                .map_err(CircuitError::PathSelection)?;
            let onion = build_circuit(&path, enveloped.to_vec())?;

            let first_hop_addr = path[0].address.clone();
            let exit_relay_id = path.last().unwrap().id.clone();

            let mut stream = TcpStream::connect(&first_hop_addr).await?;
            write_frame(&mut stream, &onion).await?;

            sent.push(SentCircuit { exit_relay_id });
        }

        Ok(sent)
    }

    /// Starts continuous background cover traffic: dummy cells sent
    /// through freshly selected circuits at randomized intervals
    /// within `[min_interval, max_interval)`, indistinguishable on
    /// the wire from real sends. Call `.abort()` on the returned
    /// handle to stop.
    pub fn spawn_cover_traffic(
        &self,
        min_interval: Duration,
        max_interval: Duration,
    ) -> JoinHandle<()> {
        cover_traffic::spawn(
            self.topology.clone(),
            self.hop_count,
            min_interval,
            max_interval,
        )
    }
}
