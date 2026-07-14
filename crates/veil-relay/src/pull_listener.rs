//! A tiny network protocol letting a receiving client pull whatever
//! cells are currently queued in a relay's [`crate::mailbox::Mailbox`].
//!
//! Wire protocol, one request per TCP connection:
//! ```text
//! client -> server: single byte, 0x01 ("PULL")
//! server -> client: 4-byte big-endian count, then that many
//!                    length-prefixed frames (see
//!                    crate::forwarding::{read_frame, write_frame})
//! ```
//! then the connection closes. No authentication and no per-recipient
//! addressing — every connected client receives every currently
//! queued cell. This is safe because cells are opaque ciphertext to
//! anyone but their intended recipient; see `mailbox.rs`.
//!
//! Runs on `listen_addr.port() + 1000` by convention (see
//! `veil-relay::main`), rather than as a config field, to keep this
//! additive and avoid changing `RelayConfig`'s shape for existing
//! deployments. A dedicated config field is reasonable future work.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::forwarding::{read_frame, write_frame};
use crate::mailbox::Mailbox;

const PULL_REQUEST_BYTE: u8 = 0x01;

/// Runs forever, accepting pull requests on `listen_addr` and serving
/// whatever is currently queued in `mailbox`.
pub async fn serve(listen_addr: std::net::SocketAddr, mailbox: Mailbox) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "mailbox pull listener ready");

    loop {
        let (stream, peer) = listener.accept().await?;
        let mailbox = mailbox.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_pull(stream, mailbox).await {
                warn!(%peer, error = %e, "pull request failed");
            }
        });
    }
}

async fn handle_pull(mut stream: TcpStream, mailbox: Mailbox) -> std::io::Result<()> {
    let mut request = [0u8; 1];
    stream.read_exact(&mut request).await?;
    if request[0] != PULL_REQUEST_BYTE {
        return Ok(()); // unrecognized request — drop the connection
    }

    let cells = mailbox.drain().await;
    stream
        .write_all(&(cells.len() as u32).to_be_bytes())
        .await?;
    for cell in cells {
        write_frame(&mut stream, &cell).await?;
    }
    Ok(())
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

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pull_returns_queued_cells_and_empties_the_mailbox() {
        let mailbox = Mailbox::new();
        mailbox.push(b"first".to_vec()).await;
        mailbox.push(b"second".to_vec()).await;

        let addr: std::net::SocketAddr = "127.0.0.1:29500".parse().unwrap();
        let server_mailbox = mailbox.clone();
        tokio::spawn(async move {
            let _ = serve(addr, server_mailbox).await;
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
            let _ = serve(addr, server_mailbox).await;
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
            let _ = serve(addr, server_mailbox).await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let first = pull("127.0.0.1:29502").await.unwrap();
        assert_eq!(first, vec![b"batch-one".to_vec()]);

        mailbox.push(b"batch-two".to_vec()).await;
        let second = pull("127.0.0.1:29502").await.unwrap();
        assert_eq!(second, vec![b"batch-two".to_vec()]);
    }
}
