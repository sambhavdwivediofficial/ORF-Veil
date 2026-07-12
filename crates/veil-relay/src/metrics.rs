//! Lock-free counters tracking relay activity.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub cells_forwarded: AtomicU64,
    pub cells_delivered: AtomicU64,
    pub decrypt_failures: AtomicU64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            cells_forwarded: self.cells_forwarded.load(Ordering::Relaxed),
            cells_delivered: self.cells_delivered.load(Ordering::Relaxed),
            decrypt_failures: self.decrypt_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub cells_forwarded: u64,
    pub cells_delivered: u64,
    pub decrypt_failures: u64,
}
