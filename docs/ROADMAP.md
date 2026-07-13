# Roadmap

Veil is under active, early development. This document tracks what exists
today, what's next, and what's intentionally deferred. Status reflects
the state of the codebase, not aspirations — an item is only checked once
it is implemented, tested, and wired into the running system (not just
present as unused library code).

---

## v0.1 — Core fabric (current)

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

Everything here is tracked against a specific, named gap in
[`THREAT_MODEL.md`](THREAT_MODEL.md) — this phase is about making the
system's actual behavior match its stated privacy properties, not adding
new features.

- [ ] Wire up scheduled dummy/cover traffic on running relays (the
      generator exists in `veil-routing::dummy_traffic`; nothing calls it
      on a schedule yet)
- [ ] Fixed-size (Sphinx-style) onion layer padding, so cell size no
      longer correlates with circuit depth
- [ ] Persistent relay identity (implement `static_secret_hex` loading,
      currently a stub in `veil-relay::main`)
- [ ] Receiving client: a way for a separate process to pull delivered
      cells from an exit relay over the network, rather than only
      observing delivery in-process

## v0.3 — Real deployment shape

- [ ] Multi-cell message reassembly on the receiving side, across cells
      that may exit through different relays
- [ ] Topology discovery / distribution — a way for a client to learn
      about relays it doesn't already have hardcoded, rather than being
      constructed with a fixed `Topology`
- [ ] QUIC transport between relays (currently plain TCP; see
      `ARCHITECTURE.md`)
- [ ] Basic connection/request rate limiting on relays (`max_connections`
      is currently parsed from config but not enforced)
- [ ] `docker-compose` demo network wired to an actual client (currently
      the compose file starts real, reachable relay containers, but
      `veil-cli` only knows how to talk to relays it spins up itself —
      see the note in `docker/docker-compose.yml`)

## Later / exploratory

Deliberately unscheduled — these need design work before they're
implementation-ready, and are listed here so they aren't forgotten, not
because they're imminent.

- [ ] Sybil-resistant or reputation-weighted relay selection
- [ ] NAT traversal for relays not on a public IP
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
