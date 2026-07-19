//! Client integration library for applications sending and receiving
//! messages through the Veil relay fabric.

pub mod client;
pub mod cover_traffic;
pub mod envelope;
pub mod receiver;
pub mod session;

pub use client::{ClientError, SentCircuit, VeilClient};
pub use receiver::{receive, ReceiveError, Receiver};
pub use session::Session;
