# Roadmap

Veil is under active, early development. This document tracks what exists
today, what's next, and what's intentionally deferred. Status reflects
the state of the codebase, not aspirations — an item is only checked once
it is implemented, tested, and wired into the running system (not just
present as unused library code).

---

## v0.1 — Core fabric

The cryptographic core, relay forwarding, circuit construction, and a
working send path exist and are tested end-to-end over real sockets.

- [x] Fixed-size cell format, fragmentation, reassembly (`veil-core`)
- [x] Per-cell ChaCha20-Poly1305 encryption, X25519 key exchange, HKDF key derivation (`veil-core`)
- [x] Relay node: TCP listener, onion-layer peeling, connection-pooled forwarding (`veil-relay`)
- [x] Random per-cell path selection, non-repeating hops (`veil-routing`)
- [x] Full nested-onion circuit construction (`veil-routing::build_circuit`)
- [x] Client send path: fragment → encrypt → route → send (`veil-sdk`)
- [x] Local demonstration harness proving the full stack works together (`veil-cli`)
- [x] Unit tests per crate + cross-crate integration tests over real sockets (`tests/integration`)
- [x] CI (build + test on Linux and Windows) and multi-platform release builds

## v0.2 — Close the honest gaps in the threat model

Everything here was tracked against a specific, named gap in
[`THREAT_MODEL.md`](THREAT_MODEL.md) — this phase was about making the
system's actual behavior match its stated privacy properties, not adding
unrelated new features.

- [x] Persistent relay identity: `static_secret_hex` loading, plus
      `veil-relay-keygen` to generate one (`veil-relay::main`,
      `veil-core::crypto::KeyPair::{to_hex, from_hex}`)
- [x] Receiving client: a genuinely separate process can pull delivered
      cells from a relay's mailbox over the network
      (`veil-relay::pull_listener`, `veil-sdk::receiver`), rather than
      only observing delivery in-process
- [x] Sender-identity envelope: the sender's ephemeral public key now
      travels with the delivered cell (`veil-sdk::envelope`), which the
      receiving-client work above depends on — without it, a genuinely
      separate recipient process had no way to learn which key to
      derive
- [x] Cover traffic: `VeilClient::spawn_cover_traffic` sends dummy
      cells through freshly selected circuits at randomized intervals,
      wrapped identically to real sends (`veil-sdk::cover_traffic`,
      building on the generator in `veil-routing::dummy_traffic`)
- [ ] Fixed-size (Sphinx-style) onion layer padding, so cell size no
      longer correlates with circuit depth — deliberately deferred, see
      "Explicitly deferred" below

## v0.3 — Real deployment shape

- [x] Multi-cell message reassembly on the receiving side: `veil-sdk::Receiver`
      keeps a `Reassembler` alive across repeated polls, so fragments
      that exit through different relays at different times still
      recombine into the original message
- [x] Topology discovery: relays answer a DESCRIBE request with their
      own id, public key, and address (`veil-relay::pull_listener::describe`,
      `veil-routing::discovery::discover_topology`), so a client can
      build a `Topology` from nothing but a list of addresses instead
      of needing every public key copied in by hand
- [x] External topology loading from a JSON file
      (`veil-routing::topology_file`), and a full Docker Compose
      deployment that a client can actually route through — including
      a dockerized client service that resolves relays via Docker's
      internal DNS (`docker/docker-compose.yml`)
- [x] Connection rate limiting on relays: `max_connections` is now
      enforced via a semaphore at accept time, with rejections tracked
      in relay metrics (`veil-relay::node`)
- [ ] QUIC transport between relays (currently plain TCP; see
      `ARCHITECTURE.md`) — deferred, see below

## Explicitly deferred (not forgotten, deliberately postponed)

These aren't "later, maybe" items — they're gaps that were evaluated
and deliberately not attempted yet, because doing them carelessly would
be worse than the current, honestly-documented gap:

- **Sphinx-style fixed-size padding.** A naive version of this (every
  onion layer padded to one constant size) is mathematically
  impossible with simple recursive nesting — an outer layer would need
  capacity to hold a same-size copy of itself, which has no solution.
  Real Sphinx solves this with a fixed maximum packet size and a
  PRG-derived filler scheme that reclaims header space as layers are
  peeled, which is a real cryptographic protocol design effort, not a
  quick patch. Attempting a shortcut version risks shipping something
  that *looks* fixed-size without actually closing the leak — worse
  than the current documented gap, because it would create false
  confidence.
- **QUIC transport.** Would mean rewriting the relay networking layer
  (`node.rs`, `forwarding.rs`) and adding TLS certificate handling —
  a large, high-blast-radius change against code that is currently
  fully tested and working over TCP.
- **NAT traversal.** A separate research area (STUN/TURN, hole
  punching) or reliance on relay operators port-forwarding — out of
  scope until the rest of the protocol is more mature.

## Later / exploratory

Deliberately unscheduled — these need design work before they're
implementation-ready, and are listed here so they aren't forgotten, not
because they're imminent.

- [ ] Sybil-resistant or reputation-weighted relay selection
- [ ] Mobile/desktop client integration
- [ ] Independent security review

---

## Explicitly not planned

- A GUI or consumer-facing app. Veil is a transport-layer privacy
  primitive meant to be integrated beneath other applications, not a
  standalone product (see `README.md`, "What Veil Does Not Do").
- Backwards compatibility guarantees before v1.0. Wire format and APIs
  may change between minor versions while the protocol is still being
  proven out.
