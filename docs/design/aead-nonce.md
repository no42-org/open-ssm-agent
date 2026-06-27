# AEAD nonce construction (coordinator ↔ agent)

- **Status:** proposed — operationalizes [AD-27] for implementation.
- **Tracks:** [#2](https://github.com/no42-org/open-ssm-agent/issues/2)
- **Scope:** the `Envelope.ciphertext` seal on the `ControlChannel`. Not yet
  implemented; this note is the spec the AEAD adapter must follow when it lands.

## Governing decision

AD-27 mandates that all coordinator↔agent payloads (control **and** stream) are
end-to-end authenticated-encrypted, with the broker outside the trust boundary:

> The per-session AEAD key is derived from the mTLS handshake (RFC 5705 exporter)
> or an X25519 exchange bound to both certs; **AES-256-GCM** with a per-session
> **monotonic, seq-derived nonce that is never reused.**

This note pins down *how* "never reused" is guaranteed by construction, which the
architecture security review (F5) flagged as catastrophic if done naively —
"a single repeated nonce under one key breaks confidentiality and forgeability",
and naive per-process counters collide across stateless coordinators (AD-24) and
agent restarts (AD-22).

## Threat

AES-256-GCM requires the pair `(key, nonce)` to be unique for the life of the
key. Two ways the original "`seq` is the nonce" framing reused a nonce:

1. **Restart / reconnect.** `seq` resets to 0; if the key persisted, `(key, 0)`
   repeats.
2. **Shared direction.** If one key seals both directions, coordinator and agent
   both draw from the same `seq` space and collide.

## Invariant

Uniqueness is made **structural**, not dependent on a global counter:

1. **Per-session key.** A fresh `K_s` is derived per session — RFC 5705 exporter
   over the mTLS session, or X25519 bound to both certs (AD-27). A reconnect
   mints a new `sid` with a higher epoch (AD-30), hence a new `K_s`; `seq` may
   therefore safely restart at 0 each session.
2. **Per-direction subkeys.** Split `K_s` into directional keys so the two peers
   never share nonce space:
   - `K_c2a = HKDF(K_s, "osa/v1 c2a")`  — coordinator → agent
   - `K_a2c = HKDF(K_s, "osa/v1 a2c")`  — agent → coordinator
3. **Nonce = seq counter.** The 96-bit GCM nonce is the envelope `seq`
   (`uint64`, big-endian) left-padded with four zero bytes:
   `nonce = 0x00000000 ‖ seq_be64`. Because each directional key is unique to one
   `(session, direction)` and `seq` is strictly monotonic within a session,
   `(K_dir, nonce)` is unique by construction — no direction bit needed in the
   nonce, since the *key* already separates directions.
4. **Rekey threshold.** A new session is the normal rekey (new `sid` → new
   `K_s`). For long-lived sessions, re-handshake before either a message-count or
   time bound is reached, well under GCM's per-key limits. The `uint64` `seq`
   space is not the binding constraint; the rekey policy is.

## Cleartext vs sealed

Per AD-9 / AD-27 the broker routes on cleartext and never sees plaintext:

| Field | Visibility | Why |
| --- | --- | --- |
| `host_id`, `sid`, `seq`, `kind` | cleartext | broker routing + ordering/dedup (AD-8) |
| `ciphertext` | AEAD-sealed | the capability/control body — broker can never read it |

`seq` thus does double duty: cleartext routing/ordering key **and** the nonce
counter for the (separate, secret) directional key. Exposing the counter is safe;
GCM's security rests on key secrecy + nonce uniqueness, not nonce secrecy.

## Replay

The receiver tracks the highest accepted `seq` per `(K_dir)` and rejects any
`seq` ≤ it (AD-8 dedup), so a broker replay of a sealed frame is dropped before
decryption is trusted.

## Deferred to implementation

- AEAD library selection and the exact HKDF labels/salt (the `"osa/v1 …"` strings
  above are placeholders to be frozen with the adapter).
- The concrete rekey threshold values (message count / time).
- Whether stream frames (PTY/port bytes) share the directional key with control
  frames or derive a third subkey.

[AD-27]: the architecture spine, decision AD-27 (end-to-end encryption; broker untrusted).
