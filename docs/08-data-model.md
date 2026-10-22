# 08 — Data Model

All identifiers are UUIDv7 (time-ordered) unless stated. Timestamps are RFC 3339 UTC. "Encrypted" means the field lives inside an encrypted record; the columns listed as cleartext are the only ones visible to storage or the sync relay.

## Local vault (SQLite)

### `header` (one row)

| Column | Type | Notes |
|---|---|---|
| vault_id | UUID | |
| format_version | int | starts at 1 |
| argon2_params | JSON | m, t, p, profile |
| salt_pw | blob(16) | |
| wrapped_vk_pw | blob | XChaCha wrap |
| wrapped_vk_pk | blob? | passkey wrap |
| wrapped_vk_rec | blob? | recovery wrap |
| passkey_cred_id | blob? | WebAuthn credential id |
| created_at | ts | |

### `records`

| Column | Type | Notes |
|---|---|---|
| record_id | UUID | |
| kind | text | `secret`, `secret_meta`, `policy`, `handle`, `grant`, `caller`, `setting` |
| version | int | monotonically increasing per record |
| nonce | blob(24) | |
| ciphertext | blob | includes Poly1305 tag |
| updated_at | ts | |
| deleted | bool | tombstone for sync |
| sync_state | text | `local`, `pushed`, `conflict` |

Encrypted payloads (as JSON inside ciphertext):

**secret**
```json
{ "secret_id": "…", "type": "api_key", "value": "sk-…",
  "fields": { "client_id": "…", "client_secret": "…" },   // for multi-field types
  "version": 3, "created_at": "…" }
```

**secret_meta**
```json
{ "secret_id": "…", "name": "openai", "provider": "openai", "tags": ["personal"],
  "upstreams": ["api.openai.com"], "notes": "…", "no_scrub": false,
  "allow_injection": false, "rotation": { "last": "…", "adapter": "openai" } }
```

Splitting value and metadata lets the UI list secrets after unlock without decrypting values, and lets scrubber-automaton rebuilds decrypt values in one pass.

**policy** — the YAML document from [07](07-broker-and-policy.md) as JSON, plus `policy_id`, `name`.

**handle**
```json
{ "handle_id": "…", "handle_hash": "<blake3 hex>", "secret_id": "…", "policy_id": "…",
  "label": "cursor on laptop", "callers": ["mcp:cursor"], "created_at": "…",
  "expires_at": "…", "revoked_at": null, "use_count": 1234, "last_used_at": "…",
  "remembered": ["POST /v1/customers"], "canary": false, "on_anomaly": "throttle",
  "status": { "state": "throttled", "until": "…" }, "last_anomaly": { "kind": "denial_burst", "detail": "…", "at": "…", "response": "throttle" } }
```
The handle string itself is never stored. `status` is one of `normal`, `throttled` (with `until`), `approval_required`, `paused`; `on_anomaly` one of `alert`, `throttle`, `approve`, `pause`, `lock` (see [07](07-broker-and-policy.md#caps-canaries-and-unusual-activity)). Records written before these fields existed read as normal, throttle-on-anomaly handles.

**caller**
```json
{ "caller_id": "mcp:cursor", "kind": "mcp|device|process", "display": "Cursor",
  "public_key": "<ed25519 hex>?", "token_hash": "<blake3>?", "created_at": "…", "approved": true }
```

**grant** (delegation, Phase 3) — owner side
```json
{ "grant_id": "…", "secret_id": "…", "policy_id": "…", "grantee": { "account_id": "…", "email": "…" },
  "broker": { "pk": "…", "attestation_pcr0": "…?" }, "envelope_version": 1,
  "expires_at": "…", "status": "invited|active|paused|revoked", "created_at": "…" }
```

### `audit`

| Column | Type | Notes |
|---|---|---|
| seq | int PK | |
| ts | ts | cleartext (needed for range queries) |
| kind | text | cleartext: `use`, `deny`, `egress_blocked`, `approval_requested`, `approval_decided`, `reveal`, `inject`, `unlock`, `lock`, `secret_created`, `secret_updated`, `secret_deleted`, `handle_created`, `handle_revoked`, `handle_resumed`, `policy_changed`, `anomaly`, `canary_tripped`, `audit_tampered`, `grant_*`, `sync_*` |
| prev_hash | blob(32) | cleartext chain |
| this_hash | blob(32) | BLAKE3 of canonical event |
| nonce, ciphertext | blob | encrypted event body |
| signature | blob? | broker signature (delegation) |

### `audit_head`

One row (`id = 1`), replaced in the same transaction as every `audit` append.

| Column | Type | Notes |
|---|---|---|
| seq | int | `seq` of the newest audit row |
| hash | blob(32) | its `this_hash` |
| mac | blob(32) | `BLAKE3_keyed(HKDF(VK, "usk/audit-head/v1"), seq ‖ hash)` |

Absent on vaults written before 0.1.2 until their next event. See [06](06-cryptography.md#audit-log-integrity).

Encrypted body example (`use`):
```json
{ "request_id": "…", "handle_id": "…", "secret_id": "…", "caller": "mcp:cursor",
  "method": "POST", "host": "api.openai.com", "path": "/v1/chat/completions",
  "status": 200, "bytes_in": 812, "bytes_out": 4096, "latency_ms": 913,
  "policy_rule": "POST /v1/chat/completions", "scrubbed": 0 }
```

Never in an audit event: secret values, request/response bodies, full headers.

## Cloud (Postgres, Phase 3)

```
accounts(account_id, email_hash, email_enc, created_at, status)
passkeys(cred_id, account_id, public_key, sign_count, transports, created_at)
devices(device_id, account_id, public_key, display, platform, approved_at, revoked_at)
vaults(vault_id, account_id, created_at)
workspaces(workspace_id, name_enc, created_at)
workspace_members(workspace_id, account_id, role, wrapped_wk)
sync_records(vault_id, record_id, version, kind_enc?, nonce, ciphertext, size, updated_at, deleted)
grants(grant_id, owner_account_id, grantee_account_id, envelope_version, envelope_ciphertext,
       policy_hash, expires_at, status, cache_ttl, fail_mode, created_at)
grant_handles(handle_hash, grant_id, device_id, created_at, expires_at, revoked_at)
approvals(approval_id, grant_id | vault_id, requester, scope, status, created_at, decided_at)
audit_events(seq, grant_id, ts, kind, prev_hash, this_hash, body_enc, signature)
checkpoints(vault_id, day, last_hash)
leak_reports(report_id, handle_hash, source, reported_at, action)
```

- `email_hash` = BLAKE3(lowercase email + server pepper) for lookup; `email_enc` for display.
- The relay stores `sync_records.ciphertext` opaquely. `kind_enc` is optional encrypted kind to allow selective sync; default null.
- `grants.envelope_ciphertext` is decryptable only by the broker key (KMS) / enclave.

## Identifiers and formats summary

| Thing | Format |
|---|---|
| Handle | `usk_h_` + 32 base62 chars |
| Session token (local mgmt) | `usk_s_` + 32 base62 chars, file `~/.unseenkey/daemon.token` |
| MCP client token | `usk_m_` + 32 base62 chars |
| Invite code | `usk_i_` + 12 base32 chars (Crockford), single use, 24 h |
| Device id | UUIDv7 |
| Request id | UUIDv7 |

All `usk_*` prefixes are registered together with the secret-scanning partner program.

## Import formats

- `.env` (KEY=value; auto-detect provider by value pattern and key name).
- 1Password CSV/1PUX, Bitwarden JSON, KeePass XML (secure notes and logins).
- Plain paste: detect JSON (GCP SA), PEM (SSH/certs), provider prefixes.

## Export

`usk export --out vault.uskx` → the SQLite file plus a JSON manifest, encrypted as a whole with a fresh export password (Argon2id). Plaintext export exists but requires `--plaintext --i-understand` and writes a `reveal` audit event per secret.
