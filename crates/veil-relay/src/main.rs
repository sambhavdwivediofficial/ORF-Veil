use std::env;
use std::time::Duration;

use rand::rngs::OsRng;
use tracing_subscriber::EnvFilter;

use veil_core::crypto::KeyPair;
use veil_relay::config::RelayConfig;
use veil_relay::node::RelayNode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let config_path =
        env::args().nth(1).unwrap_or_else(|| "config/relay.default.toml".to_string());
    let config = RelayConfig::load(&config_path)?;

    let keypair = match &config.static_secret_hex {
        Some(hex) => load_keypair_from_hex(hex)?,
        None => {
            tracing::warn!("no static_secret_hex configured; generated an ephemeral identity for this run only");
            KeyPair::generate(&mut OsRng)
        }
    };

    let (node, mut delivery_rx) = RelayNode::new(config, keypair);

    let metrics_node = node.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let snapshot = metrics_node.metrics.snapshot();
            tracing::info!(?snapshot, "relay metrics");
        }
    });

    // Exit-point delivery is a bare log line until `veil-sdk` exists to
    // pull these cells out over a proper client protocol.
    tokio::spawn(async move {
        while let Some(delivered) = delivery_rx.recv().await {
            tracing::info!(bytes = delivered.len(), "cell delivered to local exit point");
        }
    });

    node.run().await?;
    Ok(())
}

fn load_keypair_from_hex(hex: &str) -> Result<KeyPair, Box<dyn std::error::Error>> {
    KeyPair::from_hex(hex).map_err(|e| e.into())
}
