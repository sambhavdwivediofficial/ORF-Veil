# Protocol Specification

This document specifies the wire formats used by Veil v1: the cell layout,
the per-cell encryption, and the onion-layer packet format relays use to
route cells. It is intended to be precise enough that an independent
implementation could interoperate with this one at the byte level.

Version covered: protocol version `1` (`veil_core::cell::PROTOCOL_VERSION`).

---

## 1. Cell format (`veil-core::cell::Cell`)

Every message — real or dummy — is represented on the wire as a
fixed-size **512-byte** cell before encryption.

```
Offset  Size  Field          Notes
0       1     version        must equal PROTOCOL_VERSION (1)
1       1     cell_type      0 = Data, 1 = Dummy
2       16    message_id     random, groups fragments of one message
18      2     seq_index      big-endian u16, 0-based
20      2     seq_total      big-endian u16, seq_index < seq_total
22      2     payload_len    big-endian u16, real bytes used in payload
24      488   payload        zero-padded past payload_len
```

`HEADER_SIZE = 24`, `PAYLOAD_CAPACITY = CELL_SIZE - HEADER_SIZE = 488`.

**Dummy cells** use the identical 512-byte layout with `cell_type = 1`,
a random `message_id`, `seq_index = 0`, `seq_total = 1`, and a
fully-random payload. This is what makes cover traffic effective: dummy
and data cells are byte-for-byte indistinguishable in shape, and only
decryptable by the intended recipient.

A malformed cell (unsupported version, invalid `cell_type` byte,
`payload_len` exceeding capacity, or `seq_index >= seq_total`) is rejected
at parse time (`Cell::from_bytes`) rather than propagated further into the
system.

---

## 2. Per-cell encryption (`veil-core::crypto::encryption`)

Cells are encrypted end-to-end between sender and recipient using
**ChaCha20-Poly1305**.

```
Offset  Size  Field
0       12    nonce            fresh random bytes, generated per call
12      512   ciphertext       ChaCha20-Poly1305(key, nonce, cell_bytes)
524     16    tag              Poly1305 authentication tag
```

`ENCRYPTED_CELL_SIZE = NONCE_SIZE + CELL_SIZE + TAG_SIZE = 12 + 512 + 16 = 540`.

A fresh random nonce is generated for every encryption call, so
encrypting the identical cell twice under the same key never produces
identical ciphertext — a repeated ciphertext pattern would itself be a
metadata signal.

Decryption failure (`VeilError::DecryptionFailed`) is deliberately
**undifferentiated**: a wrong key, corrupted transit data, and a forged
ciphertext all produce the identical error. A relay or client must never
be able to distinguish these cases, since doing so would give an attacker
a decryption oracle to probe the network with.

### Key derivation

The symmetric key used to encrypt cells (`session.cell_key`) is derived
from an X25519 Diffie-Hellman exchange between the sender's ephemeral
keypair and the recipient's long-term public key, expanded via
HKDF-SHA256:

```
shared  = X25519(sender_ephemeral_secret, recipient_public)
cell_key = HKDF-SHA256(salt = None, ikm = shared, info = "veil-sdk-session-v1")
```

The recipient derives the identical key using their own private key and
the sender's ephemeral public key (`Session::public_key()`), which travels
alongside the message. Domain separation via the `info` context string
ensures this key is cryptographically independent of any other key
derived from the same shared secret for a different purpose (e.g. onion
layers, below).

---

## 3. Onion layer format (`veil-relay::forwarding`)

Each hop of a circuit is wrapped in its own independently-encrypted
layer, addressed to a specific relay's static public key. A relay can
only decrypt the single layer meant for it.

```
Offset  Size       Field
0       32         ephemeral_public   sender's per-layer X25519 public key
32      12         nonce
44      N          ciphertext + tag   ChaCha20-Poly1305(layer_key, nonce, payload)
```

### Layer key derivation

```
shared    = X25519(layer_ephemeral_secret, relay_static_public)
layer_key = HKDF-SHA256(salt = None, ikm = shared, info = "veil-onion-layer-v1")
```

The relay recovers `layer_key` using its own static private key and the
`ephemeral_public` bytes carried in the frame.

### Onion payload (the plaintext inside a layer)

```
Forward:
  Offset  Size    Field
  0       1       flag = 0x00
  1       2       next_hop_len (big-endian u16)
  3       N       next_hop (UTF-8 address string, e.g. "127.0.0.1:9002")
  3+N     ...     body (opaque bytes — the next layer, or the final
                   encrypted cell if this is the last Forward)

Deliver:
  Offset  Size    Field
  0       1       flag = 0x01
  1       ...     body (opaque bytes — typically an encrypted Cell,
                   ENCRYPTED_CELL_SIZE bytes)
```

### Circuit construction

Given a path `[relay_1, relay_2, ..., relay_N]` (entry first, exit last)
and a final body (an encrypted cell), the layers are built **innermost
first**:

1. `layer_N = build_onion_layer(relay_N.public_key, Deliver { body })`
2. `layer_(i) = build_onion_layer(relay_i.public_key, Forward { next_hop: relay_(i+1).address, body: layer_(i+1) })` for `i` from `N-1` down to `1`
3. The sender transmits `layer_1` to `relay_1`'s address.

Each relay, on receipt, peels exactly one layer, and either forwards the
recovered `body` to `next_hop` (as a new frame) or, if it recovers
`Deliver`, routes `body` to its local delivery channel.

---

## 4. Framing (`veil-relay::forwarding::{read_frame, write_frame}`)

Onion layers vary in size by hop depth (see §5), so relay-to-relay TCP
connections use simple length-prefixed framing:

```
Offset  Size  Field
0       4     length (big-endian u32) — byte length of body that follows
4       N     body — the onion frame described in §3
```

---

## 5. Known v1 protocol limitation

Onion layer size is **not** padded to be constant across hop depth. An
outer layer (closer to the entry relay) is larger than an inner layer
(closer to the exit) by roughly `next_hop_len + 3` bytes per hop it
wraps. A passive observer with visibility into a relay-to-relay link
could use this size delta to estimate a cell's approximate position
within its circuit.

Fixed-size, Sphinx-style padding (where every layer, regardless of depth,
is padded to one constant size) closes this gap and is planned for a
future protocol version. See [`ROADMAP.md`](ROADMAP.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 6. Cryptographic primitives summary

| Purpose | Primitive | Notes |
|---|---|---|
| Cell / onion-layer encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit random nonce per call |
| Key exchange | X25519 | Curve25519 Diffie-Hellman |
| Key derivation | HKDF-SHA256 | Domain-separated via `info` context strings |

| Context string | Used for |
|---|---|
| `"veil-sdk-session-v1"` | Sender ↔ recipient cell encryption key |
| `"veil-onion-layer-v1"` | Per-hop onion layer key |
