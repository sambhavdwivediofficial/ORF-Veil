# Threat Model

This document states, as precisely as possible, what Veil v1 protects
against, what it does not, and what has not been independently verified.
Read this before relying on Veil for anything sensitive. If any claim
here turns out to be wrong, that is a bug in the documentation as much as
in the code — please open an issue.

Veil has not been externally audited. Nothing in this document should be
read as a guarantee.

---

## Adversary model

We consider three adversary capabilities, in increasing strength:

1. **Passive external observer** — can see encrypted traffic on the wire
   between a client and a relay, or between two relays, but controls no
   relay and cannot read relay-internal state.
2. **Malicious relay operator** — runs one or more relays honestly at the
   protocol level (forwards cells as instructed) but logs and analyzes
   everything it sees: connection metadata, cell timing, cell sizes, and
   the plaintext of any layer it successfully decrypts.
3. **Colluding relay operators** — multiple malicious relays share what
   they individually observed, attempting to correlate observations
   across hops.

We do **not** currently model an adversary that can compromise the
sender's or recipient's endpoint device directly (see "Out of scope"
below).

---

## What Veil protects against (v1)

- **A single relay reading message content.** Each relay decrypts only
  the one onion layer addressed to it. The innermost payload — the
  actual encrypted cell — is opaque to every relay except the sender and
  recipient, who share a key derived independently via X25519 + HKDF
  (see `PROTOCOL_SPEC.md` §2).
- **A single relay learning the full circuit.** A relay recovers only
  `next_hop` (the immediately following address) or a `Deliver` marker.
  It does not see the entry point, the exit point, or any hop beyond its
  immediate neighbor, unless it *is* that neighbor.
- **Linking a message's fragments via shared circuit reuse.** Every cell
  of a fragmented message is routed through an independently, randomly
  selected path (`veil-sdk::VeilClient::send` draws a fresh path per
  cell). A relay that sees one fragment of a message gains no structural
  guarantee it will see any other fragment of that same message.
- **Tampering and forged cells.** ChaCha20-Poly1305 is an AEAD
  construction; any bit-flip in transit, or an attempt to forge a cell
  without the key, is rejected at decryption. Decryption failure is
  reported identically regardless of cause (wrong key vs. corruption vs.
  forgery), so a relay cannot use error responses as an oracle.
- **Size-based content inference within a single cell.** All cells,
  real or dummy, are exactly 512 bytes before encryption. A relay cannot
  distinguish a one-byte message from a near-maximum one by cell size
  alone.
- **Relay identity spoofing across restarts.** A relay's identity is a
  persisted X25519 keypair (`static_secret_hex`, generated via
  `veil-relay-keygen`), not a fresh ephemeral one on every startup. A
  client that has recorded a relay's public key can detect if that
  relay's identity changes unexpectedly between runs.

---

## What Veil does **not** yet protect against (honest v1 gaps)

- **Cell-count-based size inference, unless cover traffic is enabled.**
  A single cell's size is fixed, but the *number* of cells a message
  requires is still visible to anyone who can count cells on the same
  circuit or timeframe. `VeilClient::spawn_cover_traffic`
  (`veil-sdk::cover_traffic`) sends dummy cells — cryptographically
  indistinguishable from real ones — through randomly selected circuits
  at randomized intervals, but it is **opt-in and not started
  automatically** by the client or relay. An application that never
  calls it gets no cell-count protection in practice, even though the
  mechanism exists and is tested.
- **Timing correlation, for the same reason.** A global or
  well-positioned passive observer who can see traffic entering and
  leaving the fabric may correlate send/receive timing to link sender
  and receiver, especially when cover traffic is not running. This is
  the classic end-to-end timing correlation attack that all low-latency
  mixnets and onion-routing systems (including Tor) face to varying
  degrees; enabling cover traffic raises the cost of this attack but
  does not eliminate it, and Veil has not implemented additional timing
  defenses such as batching or mixing delay.
- **Circuit-position inference from packet size.** Onion layer size
  currently grows with hop depth rather than being padded to a constant
  size (see `PROTOCOL_SPEC.md` §5). A relay-to-relay observer may be able
  to estimate a cell's approximate position in its circuit from this size
  delta. See `ROADMAP.md` — this is deliberately deferred, not merely
  unscheduled, because a rushed fix here would be worse than the honest
  current gap.
- **Sybil / malicious topology injection.** Path selection
  (`veil-routing::path_selection::select_path`) trusts whatever
  `Topology` it is given, whether built from a static file
  (`topology_file`) or from live discovery
  (`veil-routing::discovery::discover_topology`). Discovery makes it
  *easier* to add relays to a topology, which does not by itself make
  the topology more trustworthy — there is still no mechanism to detect
  or resist an adversary who controls a disproportionate share of
  relays a client is configured to route through.
- **First/last hop exposure to relay operators.** The entry relay always
  learns the sender's real network address (it accepts the sender's
  direct TCP connection); the exit relay always learns the destination
  address it forwards `Deliver` bodies toward. Neither relay learns the
  *other* end, but each learns the endpoint it directly touches — as in
  any onion-routing design, running your own entry or exit relay narrows
  what an adversary needs to observe.

---

## Explicitly out of scope

- **Endpoint compromise.** If the sender's or recipient's device is
  compromised, no transport-layer privacy design protects the data on
  that device.
- **Global passive adversary with total network visibility.** No
  practical low-latency system (Veil included) fully resists an adversary
  who can observe *all* traffic *everywhere* simultaneously with
  unlimited resources. Veil aims to raise the cost of traffic analysis
  substantially, not to provide theoretical unconditional anonymity
  against an unbounded adversary.
- **Denial of service, beyond basic connection limits.** Each relay
  enforces `max_connections` (a semaphore-bounded cap on concurrent
  inbound connections, rejecting new ones immediately once full — see
  `veil-relay::node`), which limits one specific resource-exhaustion
  vector. Nothing here defends against bandwidth flooding, per-connection
  request flooding, or other availability attacks.
- **Anonymity of relay operators.** Running a relay does not itself hide
  the fact that you are running a relay, or protect the relay operator's
  own identity.
- **Legal or regulatory compliance.** Veil makes no claim of compliance
  with any jurisdiction's law or any industry standard.
- **Application-layer metadata.** Anything the application built on top
  of Veil chooses to leak (e.g. embedding a username in the message
  payload) is outside what a transport-layer privacy primitive can
  protect.

---

## A note on trust assumptions

Veil's core privacy property — no single relay sees both sender and
receiver — holds as long as **at least one relay in a given circuit is
honest**. If every relay in a circuit is operated by, or colludes with,
the same adversary, that adversary can trivially reconstruct the circuit.
Path diversity (drawing relays from operators who do not collude) is a
property of the `Topology` a client is configured with, not something the
protocol itself can enforce.
