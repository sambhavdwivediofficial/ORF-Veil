# Architecture

This document describes how Veil is put together: the crate boundaries, the
data flow from sender to receiver, and the design principles behind each
decision. For the wire-level byte layout of cells and onion packets, see
[`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md). For what this architecture does and
does not protect against, see [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## Crate graph

```
veil-core (no networking, no I/O)
    ▲
    │
veil-relay (networking: TCP listener, onion peeling, forwarding)
    ▲
    │
veil-routing (path selection + circuit construction, depends on veil-relay
    ▲          for onion-layer primitives)
    │
veil-sdk (client-facing API: fragment, encrypt, route, send)
    ▲
    │
veil-cli (demonstration harness, depends on all of the above)
```

Dependencies point one direction only — `veil-core` knows nothing about
networking or routing, and `veil-relay` knows nothing about circuits or
clients. This is deliberate: a crate with fewer responsibilities is easier
to audit, test in isolation, and reuse in a context nobody has thought of
yet.

| Crate | Responsibility | Depends on |
|---|---|---|
| `veil-core` | Cell wire format, fragmentation/reassembly, per-cell AEAD encryption, X25519 key exchange | — |
| `veil-relay` | Relay node binary + library: TCP listener, onion-layer peeling, connection-pooled forwarding | `veil-core` |
| `veil-routing` | Relay directory (`Topology`), random path selection, full circuit (nested onion) construction | `veil-core`, `veil-relay` |
| `veil-sdk` | Client library: fragment → encrypt → route → send, session key management | `veil-core`, `veil-relay`, `veil-routing` |
| `veil-cli` | Local demonstration harness: spins up N in-process relays and sends a real message through them | all of the above |

---

## Data flow: sending a message

```
                     veil-sdk::VeilClient::send()
                              │
                              ▼
                 ┌─────────────────────────┐
                 │  veil-core::fragment_    │   message → Vec<Cell>,
                 │  message()               │   one random MessageId
                 └────────────┬─────────────┘   shared across all cells
                              │
                for each Cell:│
                              ▼
                 ┌─────────────────────────┐
                 │  veil-core::encrypt_cell │   ChaCha20-Poly1305 under
                 │  (session.cell_key)      │   the sender↔recipient key
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │  veil-routing::          │   fresh random path drawn
                 │  select_path()           │   independently per cell
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │  veil-routing::          │   nested onion: exit relay's
                 │  build_circuit()         │   layer built first, then
                 └────────────┬─────────────┘   wrapped hop by hop back
                              │                  to the entry relay
                              ▼
                    TCP → path[0] (entry relay)
```

Each relay in the path only ever decrypts the single layer addressed to
it (see `veil-relay::forwarding::peel_onion_layer`), revealing either
`Forward { next_hop, body }` or `Deliver { body }`. The relay forwards
`body` — still opaque ciphertext — without ever seeing the plaintext cell,
the original sender, or any hop beyond its immediate neighbors.

---

## Why cells are fragmented and fixed-size

A message of any length is split into cells of an identical, fixed size
(`CELL_SIZE = 512` bytes, see `veil-core::cell`) before it touches the
network. An observer watching encrypted traffic cannot tell a one-byte
message from a ten-kilobyte one by looking at any single cell — only the
*count* of cells hints at size, and that is what dummy/cover traffic and
independent per-cell routing are meant to obscure (see
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the current gap here).

## Why every cell takes an independent path

`veil-sdk::VeilClient::send` calls `select_path` **inside** the per-cell
loop, not once per message. If every fragment of a message reused the same
three relays, a single relay on that path could trivially link all of that
message's cells back together by message ID or arrival pattern — which
defeats the purpose of per-cell routing. Drawing a fresh random path per
cell means no single relay, compromised or not, sees more than one
fragment of any given message.

## Why `veil-relay` is both a library and a binary

The onion-layer construction functions (`build_onion_layer`,
`peel_onion_layer`) are used by both the relay (to *peel* a layer) and the
client (to *build* one, via `veil-routing`). Keeping this logic in
`veil-relay`'s library target — rather than duplicating it in the client
— means both sides of the protocol are guaranteed to agree on the wire
format, because they are the same code.

## Transport

Relays currently communicate over plain TCP with a simple 4-byte
length-prefixed framing (see `veil-relay::forwarding::{read_frame,
write_frame}`). QUIC is the intended long-term transport — it gives
built-in encryption, stream multiplexing, and better behavior on lossy
networks — but TCP was chosen for v1 to keep the relay implementation
small enough to audit while the protocol itself was still being proven
out. See [`ROADMAP.md`](ROADMAP.md).

## Connection pooling

`RelayNode` keeps a pool of outbound TCP connections keyed by next-hop
address (`veil-relay::node::RelayNode`), so a relay forwarding many cells
to the same next hop reuses one connection instead of dialing fresh for
every cell. A stale pooled connection is detected on write failure,
evicted, and retried once with a fresh dial.

## What is intentionally *not* in this architecture yet

- **Receiving client.** `veil-sdk` can send; nothing yet exists for a
  separate process to *pull* delivered cells from an exit relay's
  delivery channel over the network. Right now, delivery is only
  observable in-process (as `veil-cli` does) or via relay logs.
- **Cover traffic scheduling.** `veil-routing::dummy_traffic` implements
  a working dummy-cell generator, but no relay or client currently calls
  it on a running schedule.
- **Persistent relay identity.** Every relay generates a fresh ephemeral
  keypair on startup (`static_secret_hex` loading is a stub). A restarted
  relay is a different cryptographic identity, which breaks any
  long-lived topology that references it by public key.
