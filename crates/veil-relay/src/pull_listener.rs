//! A tiny network protocol serving two purposes on a relay's mailbox
//! port (`listen_addr.port() + 1000` by convention):
//!
//! ```text
//! PULL      client -> server: single byte, 0x01
//!           server -> client: 4-byte count, then that many
//!                              length-prefixed frames (see
//!                              crate::forwarding::{read_frame, write_frame})
//!
//! DESCRIBE  client -> server: single byte, 0x02
//!           server -> client: relay_id (2-byte len + UTF-8 bytes),
//!                              public_key (32 raw bytes),
//!                              main_addr (2-byte len + UTF-8 bytes)
//! ```
//! Either way the connection closes after one response. No
//! authentication on either request — PULL is safe because cells are
//! opaque ciphertext to anyone but their intended recipient (see
//! `mailbox.rs`); DESCRIBE is safe because a relay's id, public key,
//! and address are meant to be public (that's the whole point of a
//! `Topology`).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use crate::forwarding::{read_frame, write_frame};
use crate::mailbox::Mailbox;

const PULL_REQUEST_BYTE: u8 = 0x01;
const DESCRIBE_REQUEST_BYTE: u8 = 0x02;

/// The self-reported identity a relay hands back on a DESCRIBE
/// request — everything a client needs to add this relay to a
/// `Topology` without already knowing its public key ahead of time.
#[derive(Debug, Clone)]
pub struct RelayIdentity {
    pub id: String,
    pub public_key: PublicKey,
    pub main_addr: String,
}

/// Runs forever, accepting PULL and DESCRIBE requests on `listen_addr`.
pub async fn serve(
    listen_addr: std::net::SocketAddr,
    mailbox: Mailbox,
    identity: RelayIdentity,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "mailbox pull listener ready");

    let identity = Arc::new(identity);

    loop {
        let (stream, peer) = listener.accept().await?;
        let mailbox = mailbox.clone();
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, mailbox, identity).await {
                warn!(%peer, error = %e, "request failed");
            }
        });
    }
}

async fn handle_request(
    mut stream: TcpStream,
    mailbox: Mailbox,
    identity: Arc<RelayIdentity>,
) -> std::io::Result<()> {
    let mut request = [0u8; 1];
    stream.read_exact(&mut request).await?;

    match request[0] {
        PULL_REQUEST_BYTE => {
            let cells = mailbox.drain().await;
            stream
                .write_all(&(cells.len() as u32).to_be_bytes())
                .await?;
            for cell in cells {
                write_frame(&mut stream, &cell).await?;
            }
        }
        DESCRIBE_REQUEST_BYTE => {
            write_len_prefixed(&mut stream, identity.id.as_bytes()).await?;
            stream.write_all(identity.public_key.as_bytes()).await?;
            write_len_prefixed(&mut stream, identity.main_addr.as_bytes()).await?;
        }
        _ => {} // unrecognized request — drop the connection
    }
    Ok(())
}

async fn write_len_prefixed(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(&(bytes.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(bytes).await
}

async fn read_len_prefixed_string(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    String::from_utf8(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not valid utf-8"))
}

/// Client-side helper: connect to a relay's mailbox listener and pull
/// everything currently queued there.
pub async fn pull(addr: &str) -> std::io::Result<Vec<Vec<u8>>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(&[PULL_REQUEST_BYTE]).await?;

    let mut count_buf = [0u8; 4];
    stream.read_exact(&mut count_buf).await?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        cells.push(read_frame(&mut stream).await?);
    }
    Ok(cells)
}

/// Client-side helper: ask a relay who it is. `addr` is the relay's
/// mailbox address (main port + 1000), the same address [`pull`] uses.
pub async fn describe(addr: &str) -> std::io::Result<RelayIdentity> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(&[DESCRIBE_REQUEST_BYTE]).await?;

    let id = read_len_prefixed_string(&mut stream).await?;

    let mut pub_bytes = [0u8; 32];
    stream.read_exact(&mut pub_bytes).await?;
    let public_key = PublicKey::from(pub_bytes);

    let main_addr = read_len_prefixed_string(&mut stream).await?;

    Ok(RelayIdentity {
        id,
        public_key,
        main_addr,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::time::Duration;
    use veil_core::crypto::KeyPair;

    fn test_identity(id: &str, main_addr: &str) -> RelayIdentity {
        RelayIdentity {
            id: id.to_string(),
            public_key: KeyPair::generate(&mut OsRng).public_key(),
            main_addr: main_addr.to_string(),
        }
    }

    #[tokio::test]
    async fn pull_returns_queued_cells_and_empties_the_mailbox() {
        let mailbox = Mailbox::new();
        mailbox.push(b"first".to_vec()).await;
        mailbox.push(b"second".to_vec()).await;

        let addr: std::net::SocketAddr = "127.0.0.1:29500".parse().unwrap();
        let server_mailbox = mailbox.clone();
        tokio::spawn(async move {
            let _ = serve(addr, server_mailbox, test_identity("r", "127.0.0.1:9000")).await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let received = pull("127.0.0.1:29500").await.unwrap();
        assert_eq!(received, vec![b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(mailbox.len().await, 0);
    }

    #[tokio::test]
    async fn pull_on_empty_mailbox_returns_empty() {
        let mailbox = Mailbox::new();
        let addr: std::net::SocketAddr = "127.0.0.1:29501".parse().unwrap();
        let server_mailbox = mailbox.clone();
        tokio::spawn(async move {
            let _ = serve(addr, server_mailbox, test_identity("r", "127.0.0.1:9000")).await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let received = pull("127.0.0.1:29501").await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn second_pull_after_new_pushes_only_returns_the_new_ones() {
        let mailbox = Mailbox::new();
        mailbox.push(b"batch-one".to_vec()).await;

        let addr: std::net::SocketAddr = "127.0.0.1:29502".parse().unwrap();
        let server_mailbox = mailbox.clone();
        tokio::spawn(async move {
            let _ = serve(addr, server_mailbox, test_identity("r", "127.0.0.1:9000")).await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let first = pull("127.0.0.1:29502").await.unwrap();
        assert_eq!(first, vec![b"batch-one".to_vec()]);

        mailbox.push(b"batch-two".to_vec()).await;
        let second = pull("127.0.0.1:29502").await.unwrap();
        assert_eq!(second, vec![b"batch-two".to_vec()]);
    }

    #[tokio::test]
    async fn describe_returns_the_relays_own_identity() {
        let mailbox = Mailbox::new();
        let addr: std::net::SocketAddr = "127.0.0.1:29503".parse().unwrap();
        let identity = test_identity("relay-xyz", "127.0.0.1:9042");
        let expected_public_key = identity.public_key;

        tokio::spawn(async move {
            let _ = serve(addr, mailbox, identity).await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let described = describe("127.0.0.1:29503").await.unwrap();
        assert_eq!(described.id, "relay-xyz");
        assert_eq!(described.main_addr, "127.0.0.1:9042");
        assert_eq!(
            described.public_key.as_bytes(),
            expected_public_key.as_bytes()
        );
    }

    #[tokio::test]
    async fn describe_and_pull_both_work_against_the_same_listener() {
        let mailbox = Mailbox::new();
        mailbox.push(b"a real cell".to_vec()).await;

        let addr: std::net::SocketAddr = "127.0.0.1:29504".parse().unwrap();
        let server_mailbox = mailbox.clone();
        tokio::spawn(async move {
            let _ = serve(
                addr,
                server_mailbox,
                test_identity("both", "127.0.0.1:9099"),
            )
            .await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let described = describe("127.0.0.1:29504").await.unwrap();
        assert_eq!(described.id, "both");

        let pulled = pull("127.0.0.1:29504").await.unwrap();
        assert_eq!(pulled, vec![b"a real cell".to_vec()]);
    }
}
