//! `veil-relay` binary entry point.

use std::env;
use std::time::Duration;

use rand::rngs::OsRng;
use tracing_subscriber::EnvFilter;

use veil_core::crypto::KeyPair;
use veil_relay::config::RelayConfig;
use veil_relay::mailbox::Mailbox;
use veil_relay::node::RelayNode;
use veil_relay::pull_listener::{self, RelayIdentity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config/relay.default.toml".to_string());
    let config = RelayConfig::load(&config_path)?;

    let keypair = match &config.static_secret_hex {
        Some(hex) => load_keypair_from_hex(hex)?,
        None => {
            tracing::warn!("no static_secret_hex configured; generated an ephemeral identity for this run only");
            KeyPair::generate(&mut OsRng)
        }
    };

    // Mailbox pull listener runs on listen_addr's port + 1000 by
    // convention (see pull_listener.rs) — computed before config is
    // moved into RelayNode::new below.
    let mut mailbox_addr = config.listen_addr;
    mailbox_addr.set_port(mailbox_addr.port() + 1000);

    let identity = RelayIdentity {
        id: config.relay_id.clone(),
        public_key: keypair.public_key(),
        main_addr: config.listen_addr.to_string(),
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

    let mailbox = Mailbox::new();

    let listener_mailbox = mailbox.clone();
    tokio::spawn(async move {
        if let Err(e) = pull_listener::serve(mailbox_addr, listener_mailbox, identity).await {
            tracing::error!(error = %e, "mailbox pull listener stopped");
        }
    });
    tracing::info!(addr = %mailbox_addr, "receiving clients can pull deliveries from this address");

    // Every cell this relay delivers as a circuit's exit point is
    // queued in the mailbox, where a receiving client can pull it
    // over the network via `pull_listener`.
    tokio::spawn(async move {
        while let Some(delivered) = delivery_rx.recv().await {
            tracing::info!(
                bytes = delivered.len(),
                "cell delivered to local exit point, queued in mailbox"
            );
            mailbox.push(delivered).await;
        }
    });

    node.run().await?;
    Ok(())
}

fn load_keypair_from_hex(hex: &str) -> Result<KeyPair, Box<dyn std::error::Error>> {
    KeyPair::from_hex(hex).map_err(|e| e.into())
}
