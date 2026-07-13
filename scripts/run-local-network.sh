#!/usr/bin/env bash
# Starts N real veil-relay processes on localhost, each a genuine OS
# process communicating over real sockets — closer to how a real
# deployment behaves than `veil-cli`, which spins up relays in-process
# purely for its own self-contained demo.
#
# Usage: ./scripts/run-local-network.sh [hop_count]
set -euo pipefail

HOP_COUNT="${1:-3}"
BASE_PORT=9001
CONFIG_DIR="$(mktemp -d)"
PIDS=()

cleanup() {
    echo
    echo "Stopping ${#PIDS[@]} relay process(es)..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$CONFIG_DIR"
}
trap cleanup EXIT INT TERM

echo "Building veil-relay (release)..."
cargo build --release -p veil-relay

for ((i = 0; i < HOP_COUNT; i++)); do
    port=$((BASE_PORT + i))
    config_path="$CONFIG_DIR/relay-$i.toml"
    cat > "$config_path" <<EOF
listen_addr = "127.0.0.1:$port"
relay_id = "relay-$i"
max_connections = 256
EOF

    echo "Starting relay-$i on 127.0.0.1:$port"
    ./target/release/veil-relay "$config_path" &
    PIDS+=("$!")
done

echo
echo "$HOP_COUNT relay(s) running (PIDs: ${PIDS[*]}). Press Ctrl+C to stop."
wait
