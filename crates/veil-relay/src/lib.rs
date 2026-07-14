//! Split from `main.rs` so the onion-layer construction functions in
//! [`forwarding`] can be reused by circuit-building code elsewhere
//! (`veil-sdk`) without depending on the relay binary itself.

pub mod config;
pub mod forwarding;
pub mod mailbox;
pub mod metrics;
pub mod node;
pub mod pull_listener;
