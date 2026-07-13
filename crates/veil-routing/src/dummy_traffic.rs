//! Cover-traffic timing.
//!
//! Uniform cell size alone does not hide *when* real traffic occurs.
//! This generator emits dummy cells at randomized intervals so that
//! an observer watching inter-arrival timing cannot separate real
//! sends from noise.

use rand::{CryptoRng, RngCore};
use tokio::time::{self, Duration};

use veil_core::cell::Cell;

pub struct DummyTrafficGenerator {
    min_interval: Duration,
    max_interval: Duration,
}

impl DummyTrafficGenerator {
    pub fn new(min_interval: Duration, max_interval: Duration) -> Self {
        Self {
            min_interval,
            max_interval,
        }
    }

    /// Waits a randomized interval within `[min_interval, max_interval)`,
    /// then returns a dummy cell ready to send.
    pub async fn next_dummy(&self, rng: &mut (impl RngCore + CryptoRng)) -> Cell {
        let span = self
            .max_interval
            .saturating_sub(self.min_interval)
            .as_millis()
            .max(1) as u64;
        let jitter = rng.next_u64() % span;
        time::sleep(self.min_interval + Duration::from_millis(jitter)).await;
        Cell::new_dummy(rng)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn emits_a_dummy_cell_within_bounds() {
        let generator =
            DummyTrafficGenerator::new(Duration::from_millis(1), Duration::from_millis(5));
        let mut rng = OsRng;

        let start = tokio::time::Instant::now();
        let cell = generator.next_dummy(&mut rng).await;
        let elapsed = start.elapsed();

        assert_eq!(cell.cell_type(), veil_core::cell::CellType::Dummy);
        assert!(elapsed >= Duration::from_millis(1));
    }
}
