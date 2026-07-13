//! Generates a new relay identity keypair and prints it in the format
//! a relay's TOML config expects, so the identity survives restarts
//! instead of a fresh one being generated every time the relay starts.
//!
//! Usage: `cargo run --bin veil-relay-keygen`

use rand::rngs::OsRng;
use veil_core::crypto::{public_key_to_hex, KeyPair};

fn main() {
    let keypair = KeyPair::generate(&mut OsRng);

    println!("Generated a new relay identity.");
    println!();
    println!("Add this line to the relay's config file:");
    println!("  static_secret_hex = \"{}\"", keypair.to_hex());
    println!();
    println!("Public key (safe to share with clients building a topology):");
    println!("  {}", public_key_to_hex(&keypair.public_key()));
    println!();
    println!("The line above contains the relay's private key. Treat it like");
    println!("any other credential: do not commit it, do not share it, and");
    println!("keep it out of version control.");
}
