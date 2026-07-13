//! Core relay node: identity, listener, accept loop, and forwarding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use veil_core::crypto::KeyPair;

use crate::config::RelayConfig;
use crate::forwarding::{peel_onion_layer, write_frame, OnionError, OnionPayload};
use crate::metrics::Metrics;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("onion layer error: {0}")]
    Onion(#[from] OnionError),
}

/// Outbound connections keyed by next-hop address, reused across cells
/// instead of dialing fresh for every forward.
type ConnectionPool = Mutex<HashMap<String, Arc<Mutex<TcpStream>>>>;

pub struct RelayNode {
    pub config: RelayConfig,
    pub keypair: KeyPair,
    pub metrics: Arc<Metrics>,
    outbound: ConnectionPool,
    delivery_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl RelayNode {
    pub fn new(
        config: RelayConfig,
        keypair: KeyPair,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (delivery_tx, delivery_rx) = mpsc::unbounded_channel();
        let node = Arc::new(Self {
            config,
            keypair,
            metrics: Arc::new(Metrics::default()),
            outbound: Mutex::new(HashMap::new()),
            delivery_tx,
        });
        (node, delivery_rx)
    }

    pub async fn run(self: Arc<Self>) -> Result<(), RelayError> {
        let listener = tokio::net::TcpListener::bind(self.config.listen_addr).await?;
        info!(relay_id = %self.config.relay_id, addr = %self.config.listen_addr, "relay listening");

        loop {
            let (stream, peer) = listener.accept().await?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_connection(stream, peer).await {
                    warn!(%peer, error = %e, "connection closed with error");
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), RelayError> {
        use std::sync::atomic::Ordering::Relaxed;
        use tokio::io::AsyncReadExt;

        loop {
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return Ok(()); // peer closed the connection — not a relay error
            }
            let len = u32::from_be_bytes(len_buf) as usize;

            let mut frame = vec![0u8; len];
            stream.read_exact(&mut frame).await?;

            let payload = match peel_onion_layer(&self.keypair, &frame) {
                Ok(p) => p,
                Err(e) => {
                    self.metrics.decrypt_failures.fetch_add(1, Relaxed);
                    warn!(%peer, error = %e, "dropping cell that failed to peel");
                    continue;
                }
            };

            match payload {
                OnionPayload::Forward { next_hop, body } => {
                    self.forward(&next_hop, &body).await?;
                    self.metrics.cells_forwarded.fetch_add(1, Relaxed);
                }
                OnionPayload::Deliver { body } => {
                    let _ = self.delivery_tx.send(body);
                    self.metrics.cells_delivered.fetch_add(1, Relaxed);
                }
            }
        }
    }

    async fn forward(&self, next_hop: &str, body: &[u8]) -> Result<(), RelayError> {
        let conn = self.get_or_connect(next_hop).await?;
        {
            let mut guard = conn.lock().await;
            if write_frame(&mut *guard, body).await.is_ok() {
                return Ok(());
            }
        }
        // Pooled connection was stale (peer likely closed it) — drop it
        // and retry once with a fresh dial before giving up.
        self.outbound.lock().await.remove(next_hop);
        let conn = self.get_or_connect(next_hop).await?;
        let mut guard = conn.lock().await;
        write_frame(&mut *guard, body).await?;
        Ok(())
    }

    async fn get_or_connect(&self, addr: &str) -> Result<Arc<Mutex<TcpStream>>, RelayError> {
        let mut pool = self.outbound.lock().await;
        if let Some(conn) = pool.get(addr) {
            return Ok(conn.clone());
        }
        let stream = TcpStream::connect(addr).await?;
        let conn = Arc::new(Mutex::new(stream));
        pool.insert(addr.to_string(), conn.clone());
        Ok(conn)
    }
}
