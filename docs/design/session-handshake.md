# Session handshake design (coordinator ↔ agent, end-to-end sealed)

- **Status:** design — implements the seal wiring (#20) on top of the seal
  primitive (`osa-core::seal`, story 1.6) and the per-host topic isolation
  (story 3.0). Pairs with `docs/design/aead-nonce.md`.
- **Tracks:** [#20](https://github.com/no42-org/open-ssm-agent/issues/20)

## Problem

The agent and coordinator communicate **through the untrusted broker** (AD-27):
the agent's mTLS terminates at the *broker*, not the coordinator, so the broker
can read and tamper with everything that flows between them. Story 1.6 built the
AES-256-GCM seal and an X25519 key exchange, but it was never wired into the live
channel. We now need a per-session sealed channel for command/result payloads
(Epic 3).

**Why the seal's existing channel binding is not enough.** `seal::Handshake::derive`
folds the two ephemeral X25519 public keys + a caller `binding` (cert DERs) into
the HKDF. But the cert DERs are *public*, so a broker man-in-the-middle can run
two separate exchanges (one with each party, substituting its own ephemeral keys)
and re-encrypt — the identical public binding does not detect it. The ephemeral
keys must be **authenticated** to the parties' identities. This is a textbook
signature-authenticated DH (station-to-station).

## Trust setup

- Agent holds its enrollment key pair (**ECDSA P-256**, rcgen default) and its
  CA-signed mTLS cert (`SAN = urn:osa:host:<uuid>`), plus the pinned CA root.
- Coordinator holds the CA (can sign with the CA key and verify host certs), and
  the cert/key the agent presents are verifiable against it.
- Identity keys are ECDSA P-256; handshake signatures are `ECDSA_P256_SHA256`.

## Protocol

A two-message authenticated DH carried as cleartext `Envelope`s (the handshake
*establishes* the keys, so its own messages aren't sealed; they are authenticated
by signatures and bound to a fresh per-session `sid`).

1. **ClientHello** (agent → coordinator, on the agent's uplink topic):
   `{ sid, client_eph: [u8;32], cert_der, sig_c }`
   where `sig_c = ECDSA-P256(agent_key, "osa/v1 hs c2s" ‖ sid ‖ client_eph)`.
   The `cert_der` lets the coordinator recover the agent's identity public key
   and verify the chain.

2. Coordinator: verify `cert_der` chains to the CA, is unrevoked, and its SAN
   `host_id` matches the connecting tenant; verify `sig_c` against the cert's
   public key (proves the agent holds the identity key and bound *this*
   ephemeral). Generate `server_eph`; compute `shared = X25519(server_eph_priv,
   client_eph)` (reject low-order); derive the session keys (below).

3. **ServerHello** (coordinator → agent, on the agent's downlink topic):
   `{ sid, server_eph: [u8;32], sig_s }`
   where `sig_s = ECDSA-P256(ca_key, "osa/v1 hs s2c" ‖ sid ‖ client_eph ‖ server_eph)`.

   The `‖` here is the canonical length-prefixed framing the code uses
   (`push_field`: an 8-byte big-endian length before each variable field, after a
   fixed context string), not bare concatenation — so no choice of `sid` can shift
   a field boundary or make a client transcript collide with a server one.

4. Agent: verify `sig_s` against the **pinned CA root's** public key (the agent
   trusts the CA, and the signature binds both ephemerals + sid → no MITM);
   compute `shared = X25519(client_eph_priv, server_eph)` (reject low-order);
   derive the same session keys.

Both ends now hold the per-direction AES-256-GCM keys; subsequent `Envelope`s
carry sealed `ciphertext` with cleartext routing (`host_id, sid, seq, kind`) and
`seq`-as-nonce per `aead-nonce.md`.

## Key derivation

Reuse `seal::Handshake::derive(peer_eph, binding)`, which already does the
X25519 + low-order rejection + HKDF that splits into directional keys. The
`binding` = `sid ‖ client_eph ‖ server_eph ‖ cert_der` (the full transcript), so
the session keys are bound to this exact, authenticated exchange. A reconnect
mints a fresh `sid` + ephemerals → fresh keys, so `seq` may restart at 0.

## Component split

- **`osa-core::handshake` (pure, #20a):** the canonical transcripts
  (`client_transcript`, `server_transcript`), ECDSA-P256 sign/verify over a
  transcript (via the RustCrypto `p256` crate, matching osa-core's existing
  `aes-gcm`/`hkdf`/`sha2` stack), and the authenticated key-agreement that returns
  `SessionKeys` only when the peer signature verifies. Unit-tested end-to-end with
  ephemeral ECDSA keys. No cert-chain logic (that needs x509-parser, a bin dep).
- **Coordinator + agent bins (#20b):** cert-chain verification + host_id
  extraction (already have x509-parser + the CA), loading the identity/CA key to
  sign, and the MQTT uplink/downlink flow + a per-session manager. The agent
  subscribes to `/tenants/<host>/osa/v1/down`; the coordinator's bridge publishes
  ServerHello + sealed dispatches there.

## Signing-key posture (a known tradeoff)

ServerHello is signed with the **CA key**, which the agent already pins. In this
deployment the embedded CA *is* the coordinator and that key is **already online**
— it signs CSRs on every enrollment (Epic 1) — so using it to sign ServerHello
adds no new "root key online" exposure category, and cross-use is domain-separated
(`"osa/v1 hs s2c"` can never parse as a DER `TBSCertificate`). If the CA is ever
moved offline / into an HSM, ServerHello should instead be signed by a **delegated
coordinator key** carried in its own CA-issued cert that the agent chains to the
pinned root. `osa-core::handshake` is key-agnostic (`sign`/`verify` take any
key/pubkey), so that change is confined to the bins (#20b) + this doc.

## Out of scope (later)

- The actual exec capability payloads (Epic 3 stories 3.1+) ride on the sealed
  session once established.
- Rekey thresholds and whether stream frames derive a third subkey (deferred per
  `aead-nonce.md`).
