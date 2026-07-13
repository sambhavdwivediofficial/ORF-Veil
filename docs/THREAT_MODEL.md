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

---

## What Veil does **not** yet protect against (honest v1 gaps)

- **Cell-count-based size inference.** While a single cell's size is
  fixed, the *number* of cells a message requires is still visible to
  anyone who can count cells associated with the same circuit or
  timeframe. Cover traffic (dummy cells) is implemented
  (`veil-routing::dummy_traffic::DummyTrafficGenerator`) but is **not
  currently invoked on any running schedule** by the relay or client — so
  in the current running system, cell-count leakage is not yet mitigated
  in practice, only in library code that is not yet wired up.
- **Timing correlation.** A global or well-positioned passive observer
  who can see traffic entering and leaving the fabric may correlate
  send/receive timing to link sender and receiver, especially in the
  absence of active cover traffic (see above). This is the classic
  end-to-end timing correlation attack that all low-latency mixnets and
  onion-routing systems (including Tor) face to varying degrees; Veil is
  not different in kind here, and has not implemented the timing
  defenses (e.g. scheduled dummy traffic, batching/mixing delay) needed
  to meaningfully raise the cost of this attack yet.
- **Circuit-position inference from packet size.** Onion layer size
  currently grows with hop depth rather than being padded to a constant
  size (see `PROTOCOL_SPEC.md` §5). A relay-to-relay observer may be able
  to estimate a cell's approximate position in its circuit from this size
  delta.
- **Relay identity persistence.** Relays generate an ephemeral keypair
  on every startup; there is no persisted long-term identity yet. This
  means there is currently no way to build trust or reputation in a
  specific relay over time, and no protection against a relay's identity
  changing silently between runs.
- **Sybil / malicious topology injection.** Path selection
  (`veil-routing::path_selection::select_path`) trusts whatever
  `Topology` it is given. There is no mechanism yet to detect or resist
  an adversary who controls a disproportionate share of relays in a
  client's topology — full N-1 colluding-relay compromise is possible if
  an attacker controls every relay in a selected path.
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
- **Denial of service.** Nothing here rate-limits or defends relays
  against flooding, resource exhaustion, or availability attacks.
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
