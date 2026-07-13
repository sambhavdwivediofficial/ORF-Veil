//! Client integration library for applications sending messages
//! through the Veil relay fabric.

pub mod client;
pub mod session;

pub use client::{ClientError, SentCircuit, VeilClient};
pub use session::Session;
