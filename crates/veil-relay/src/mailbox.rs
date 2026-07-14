//! In-memory store of delivered cells, queryable by a receiving
//! client over the network via [`crate::pull_listener`].
//!
//! Any client that connects and asks receives *every* currently
//! queued cell — there is no per-recipient addressing at this layer.
//! That is safe, not a leak: only the intended recipient's private
//! key will successfully decrypt a given cell (see
//! `veil-sdk::receiver`), so an eavesdropper pulling the mailbox gains
//! nothing but ciphertext they cannot open.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Cheaply cloneable handle to a relay's delivery queue. Every clone
/// shares the same underlying queue.
#[derive(Clone, Default)]
pub struct Mailbox {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Mailbox {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Add a delivered cell to the mailbox.
    pub async fn push(&self, cell: Vec<u8>) {
        self.queue.lock().await.push_back(cell);
    }

    /// Remove and return every cell currently queued, oldest first.
    /// A client that pulls and gets nothing back should simply poll
    /// again later — an empty mailbox is not an error.
    pub async fn drain(&self) -> Vec<Vec<u8>> {
        let mut queue = self.queue.lock().await;
        queue.drain(..).collect()
    }

    pub async fn len(&self) -> usize {
        self.queue.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.queue.lock().await.is_empty()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[tokio::test]
    async fn push_then_drain_returns_everything_in_order() {
        let mailbox = Mailbox::new();
        mailbox.push(b"one".to_vec()).await;
        mailbox.push(b"two".to_vec()).await;

        let drained = mailbox.drain().await;
        assert_eq!(drained, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn drain_empties_the_queue() {
        let mailbox = Mailbox::new();
        mailbox.push(b"x".to_vec()).await;
        mailbox.drain().await;
        assert_eq!(mailbox.len().await, 0);
    }

    #[tokio::test]
    async fn drain_on_empty_mailbox_returns_empty_vec() {
        let mailbox = Mailbox::new();
        assert!(mailbox.drain().await.is_empty());
    }

    #[tokio::test]
    async fn shared_clones_see_the_same_queue() {
        let mailbox = Mailbox::new();
        let clone = mailbox.clone();

        clone.push(b"shared".to_vec()).await;

        assert_eq!(mailbox.len().await, 1);
    }
}
