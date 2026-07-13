#!/usr/bin/env bash
# One-shot dev environment setup: installs Rust if missing, fetches
# dependencies, and runs a full build + test pass to confirm the
# workspace is in a working state before you start changing anything.
set -euo pipefail

echo "== Veil dev environment setup =="

if ! command -v rustc >/dev/null 2>&1; then
    echo "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
else
    echo "Rust found: $(rustc --version)"
fi

echo "Fetching workspace dependencies..."
cargo fetch

echo "Building workspace (debug)..."
cargo build --workspace

echo "Running full test suite (unit + integration)..."
cargo test --workspace

echo
echo "== Setup complete =="
echo "Try: cargo run -p veil-cli -- \"hello veil\" 3"
