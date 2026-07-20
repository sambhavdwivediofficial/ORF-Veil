//! Discovers relays from nothing but their mailbox addresses and
//! prints the resulting topology as JSON — a real command-line use of
//! `discover_topology`, not just a unit test.
//!
//! Usage: `cargo run -p veil-routing --example discover_relays -- 127.0.0.1:10001 127.0.0.1:10002 ...`

use std::env;

use veil_routing::discovery::discover_topology;

#[tokio::main]
async fn main() {
    let addresses: Vec<String> = env::args().skip(1).collect();
    if addresses.is_empty() {
        eprintln!("usage: discover_relays <mailbox_addr> [mailbox_addr ...]");
        std::process::exit(1);
    }

    println!("Querying {} address(es)...", addresses.len());
    let (topology, unreachable) = discover_topology(&addresses).await;

    println!("\nDiscovered {} relay(s):", topology.len());
    println!("{}", topology.to_json());

    if !unreachable.is_empty() {
        println!("\n{} address(es) did not respond:", unreachable.len());
        for u in &unreachable {
            println!("  {} — {}", u.address, u.error);
        }
    }
}
