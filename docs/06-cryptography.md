# 06 — Cryptography

Principle: **boring, standard, reviewed**. No custom constructions. Every primitive is from a widely audited library and used in the way its authors intended. Anyone reviewing this document should be able to say "this is textbook" for every line.

## Primitives

| Purpose | Primitive | Library (Rust) |
|---|---|---|
| Password KDF | Argon2id | `argon2` (RustCrypto) |
| Key derivation | HKDF-SHA256 | `hkdf` |
| AEAD | XChaCha20-Poly1305 (24-byte nonce) | `chacha20poly1305` |
| Hashing | BLAKE3 | `blake3` |
| Signatures | Ed25519 | `ed25519-dalek` |
| Key agreement / sharing | HPKE (DHKEM X25519, HKDF-SHA256, ChaCha20-Poly1305) | `hpke` |
| Post-quantum (envelope v2) | X25519 + ML-KEM-768 hybrid KEM | `ml-kem` / `libcrux` when adopted (Open-4) |
| Randomness | OS CSPRNG | `getrandom` / `rand_core::OsRng` |
| Passkeys | WebAuthn Level 3 with PRF extension | `webauthn-rs` (server side, Phase 3); platform APIs via Tauri plugin (desktop) |
| Memory hygiene | zeroize on drop, mlock/VirtualLock | `zeroize`, `memsec` |
| Constant time | equality on handle hashes and MACs | `subtle` |

Argon2id profiles:

| Profile | Memory | Iterations | Parallelism | Target |
|---|---|---|---|---|
| `desktop` | 256 MiB | 3 | 1 | ~0.5–1 s on a 2020 laptop |
| `light` | 64 MiB | 3 | 1 | mobile / low-end / WASM |

Parameters are stored in the vault header so they can be raised over time (rewrap on next unlock).

## Key hierarchy (self mode)

```
Password ──Argon2id(salt_pw)──▶ KEK_pw ─┐
Passkey PRF ──HKDF(info="usk/kek/prf")──▶ KEK_pk ─┤
Recovery secret ──HKDF──▶ KEK_rec ─────┘
                                         each wraps ▼
                              Vault Key (VK, 32 bytes, random)
                                         │
                       HKDF(VK, info="usk/dek/<secret_id>/<version>")
                                         ▼
                      Data Encryption Key per secret version (DEK)
                                         │
                            XChaCha20-Poly1305(DEK, nonce, plaintext, aad)
```

- VK is random; unlocking = unwrapping VK with any enrolled KEK. Adding a passkey does not change VK; it adds a wrapping.
- DEKs are *derived*, not stored, so the vault stores no per-secret keys. Rotating VK (`usk rekey`) re-encrypts all records.
- `aad` = `vault_id || secret_id || version || record_type` to bind ciphertext to its position (prevents swapping records).
- Nonces are random 24 bytes (XChaCha's nonce size makes random nonces safe at any realistic volume).

### Metadata encryption

Names, tags, provider and notes are encrypted too (a separate record encrypted under a metadata DEK) so the sync relay learns only counts and sizes. A search index is built client-side after unlock. The only cleartext metadata on the relay: `record_id`, `version`, `created_at`, `size`.

### Wrapping format (VK under a KEK)

`XChaCha20-Poly1305(KEK, nonce, VK, aad="usk/vk/" || kek_kind || vault_id)`.

## Vault file format (native)

SQLite database `vault.db` with:

- `header` table: `vault_id (UUID)`, `format_version`, `argon2_params`, `salt_pw`, `wrapped_vk_pw`, `wrapped_vk_pk?`, `wrapped_vk_rec?`, `created_at`.
- `records` table: `record_id`, `kind` (`secret`, `secret_meta`, `policy`, `handle`, `grant`, `setting`), `version`, `nonce`, `ciphertext`, `updated_at`, `deleted` (tombstone).
- `audit` table: see [08](08-data-model.md); events encrypted under an audit DEK; chain hash in cleartext so integrity can be checked without unlocking.

The whole file is safe to back up or sync by any means; it contains nothing usable without a KEK.

WASM/IndexedDB uses the same record schema.

## Handles

- `handle = "usk_h_" || base62(20 random bytes)` → 32 characters after the prefix, total 38 chars. Regex `usk_h_[A-Za-z0-9]{32}`.
- The daemon stores only `BLAKE3(handle)`; lookups compare in constant time. A stolen vault file therefore does not reveal usable handles.
- A handle record links `handle_hash → secret_id, policy_id, caller_binding, created_at, expires_at, revoked_at`.

## Callers and request signing (delegation mode)

- Each grantee device generates an Ed25519 keypair at registration; private key stored in the OS keychain (Keychain / DPAPI / Secret Service).
- Every request to the hosted broker carries headers:
  - `X-Usk-Handle: usk_h_…`
  - `X-Usk-Device: <device_id>`
  - `X-Usk-Ts: <unix seconds>`
  - `X-Usk-Nonce: <16 random bytes base64>`
  - `X-Usk-Sig: Ed25519(device_sk, BLAKE3(method || path || ts || nonce || BLAKE3(body)))`
- Broker rejects if `|now − ts| > 300 s` or nonce seen within window.

For SDKs that cannot add headers, the grantee runs a **local uskd in relay mode** that adds the signature and forwards to the hosted broker. So the SDK still just points at `127.0.0.1:7391`.

## Grant envelopes (delegation mode)

```
grant_plain = { grant_id, secret_id, secret_version, secret_type, plaintext,
                upstreams, policy, expires_at, owner_id, grantee_id }
envelope_v1 = HPKE.Seal(pk_broker, info="usk/grant/v1/" || grant_id, aad=grant_id, grant_plain)
envelope_v2 = same with hybrid KEM (X25519 + ML-KEM-768)
```

- The owner's client fetches `pk_broker` from the broker service.
  - Phase 3: `pk_broker` is signed by the Unseenkey root key (pinned in clients). Trust = operator.
  - Phase 4: `pk_broker` is inside an attestation document (Nitro) that includes the enclave image hash (PCR0). The client verifies the AWS Nitro root, the PCRs against a published list, and the key binding. Trust = published, reproducible enclave image.
- The broker decrypts an envelope only inside the request path and caches the plaintext in memory for at most the grant's `cache_ttl` (default 60 s), then zeroizes.
- Rotating the secret produces a new envelope for the same `grant_id`; old envelopes are deleted.

Why not encrypt to the grantee? Because the grantee must never be able to decrypt. The broker is the only party that can, and it is designed to be unable to reveal.

## Sharing within a workspace (Phase 3)

Workspace secrets are encrypted under a Workspace Key (WK); WK is wrapped for each member's device public key (HPKE). Adding a member = one new wrapping. Removing a member = rotate WK and rewrap (lazy: on next write).

## Recovery

- At vault creation the user gets a **recovery kit**: 24 BIP-39 words (256-bit entropy) shown once, and a printable PDF/PNG with a QR code. `KEK_rec = HKDF(entropy, "usk/kek/rec")`.
- Optional (Phase 3): Shamir 2-of-3 split across a trusted contact, a file and the cloud (cloud share alone is useless).
- No account-level password reset can ever recover a vault. Say so in the UI.

## Audit log integrity

- Each event `e_n` stores `prev_hash = BLAKE3(e_{n-1} canonical bytes)`; `e_0.prev_hash = BLAKE3(vault_id)`. The chain is unkeyed, so it can be checked while locked, and so whoever can write the file can recompute it: on its own it catches edits and gaps, not a log cut short or rewritten from some point on.
- **Keyed head (local).** Every append also stores `(seq, this_hash)` of the newest event with `mac = BLAKE3_keyed(K_head, seq ‖ this_hash)`, `K_head = HKDF(VK, "usk/audit-head/v1")`, in the same transaction. An unlocked `usk log verify` checks the chain **and** that the newest row is the one the head names; without the vault key no head can be produced for a shorter or different log. A locked verify reports the head as unchecked. Logs written before this existed have no head until their next event.
- Delegation: broker signs `BLAKE3(e_n)` with its Ed25519 key; owner and grantee clients verify chain continuity and signature; gaps are shown as tampering warnings.
- Daily checkpoint: `BLAKE3(last event)` uploaded to the relay (Phase 3), for the case where the attacker has both the file and the vault key.

## Randomness and test vectors

- All randomness via `OsRng`. No user-space PRNG seeded from time.
- Fixed test vectors for every construction live in `core/tests/vectors/*.json` and are checked in CI on all targets, including WASM, to catch platform differences.

## What we deliberately do not do

- No RSA. No AES-CBC. No SHA-1. No PBKDF2 (except importing others' exports). No home-grown key stretching.
- No "encrypt with server key too" that would give the operator a second way in.
- No key escrow, no recovery through support tickets.
