# 05 — Architecture

## Components

```
                 ┌──────────────────────────────────────────────────┐
                 │                 unseenkey-core (Rust)              │
                 │  crypto · vault · policy · broker · audit · mcp   │
                 └───────┬───────────────┬────────────────┬─────────┘
                         │               │                │
              ┌──────────▼───┐   ┌───────▼───────┐   ┌────▼──────────┐
              │ usk (CLI)     │   │ uskd (daemon)  │   │ WASM (web)    │
              └──────────────┘   │ HTTP :7391    │   └───────────────┘
                                 │ MCP stdio/http│
                                 └───────▲───────┘
                                         │ Tauri IPC
                                 ┌───────┴───────┐
                                 │ Desktop app   │
                                 │ (React/TS)    │
                                 └───────────────┘

   ─────────────────────────── cloud (Phase 3+) ───────────────────────────

   ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐
   │ accounts     │  │ sync/relay   │  │ hosted broker    │  │ events   │
   │ (passkeys)   │  │ (ciphertext) │  │ (KMS → enclave)  │  │ (push)   │
   └──────────────┘  └──────────────┘  └──────────────────┘  └──────────┘
                              Postgres · object storage · KMS
```

### unseenkey-core (library crate)

Single Rust crate with feature-gated modules so the same audited code runs in the daemon, the CLI, the desktop app and the browser (WASM).

| Module | Responsibility | Depends on |
|---|---|---|
| `crypto` | KDFs, AEAD, HPKE envelopes, key hierarchy, zeroization | RustCrypto crates |
| `vault` | Encrypted store: secrets, versions, metadata, search; file format; import/export | `crypto`, `storage` |
| `storage` | Pluggable backend: SQLite (native), IndexedDB (WASM), in-memory (tests) | — |
| `policy` | Parse, validate and evaluate policies; presets | — |
| `broker` | HTTP proxy: routing, injection, host lock, egress guard, scrubbing, streaming, provider adapters (SigV4, OAuth refresh) | `vault`, `policy`, `audit` |
| `audit` | Hash-chained event log, signing, export | `crypto`, `storage` |
| `handles` | Handle generation, lookup (hashed), binding to callers | `crypto` |
| `mcp` | MCP tool definitions and server over stdio / streamable HTTP | `broker` |
| `sync` | Record versioning, E2E encryption of sync payloads, relay client | `crypto`, `vault` |
| `grants` | Delegation: invites, grant envelopes, device registration | `crypto`, `policy` |

Rule: no module other than `crypto` and `broker::inject` may hold a `SecretBytes` for longer than a function call. `SecretBytes` is a zeroizing newtype; `Display`/`Debug` are implemented to print `[secret]`.

### uskd (daemon)

- One process per user, started by the CLI or desktop app, or as a login item. Implemented as the `unseenkey-daemon` library; `usk daemon run` (auto-spawned on first use) and the `uskd` binary both run it.
- Listens on `127.0.0.1:7391` (configurable; IPv6 `::1` too). Unix domain socket / Windows named pipe also offered for the management API (planned, M2.2).
- Serves: management API (`/v1/*`, session-token auth), proxy routes (`/p/*`), MCP over streamable HTTP (`/mcp`), health (`/healthz`).
- Holds the unlocked vault key in memory (mlocked) until lock.
- Single-threaded async runtime (tokio) with a small worker pool; no plaintext crosses thread boundaries except inside a request task.

### usk (CLI)

Thin client of uskd over the management API. Starts uskd if not running. `usk run` and `usk mcp` are the only commands that touch plaintext (injection and MCP stdio), and they do so through core, not by calling the HTTP API.

### Desktop app (Tauri 2)

Rust side embeds core and manages uskd lifecycle; the UI (React + TypeScript) talks to Rust via Tauri IPC (never over HTTP, so the browser-origin problem does not apply). The webview has CSP `default-src 'self'`; no remote content.

### Web app (Phase 3, WASM)

Same core compiled to WASM. Vault decrypted in the browser. Cannot run a broker (no listening sockets) so it is for management, grants, dashboards and approvals, not for proxying.

### Cloud services (Phase 3+)

| Service | Role | Stateful? |
|---|---|---|
| `accounts` | Passkey registration/login, device registry, workspaces | Postgres |
| `sync` | Stores encrypted records per vault; versioned; delivers changes | Postgres + object storage |
| `broker-hosted` | Delegation-mode broker; stateless; pulls grant envelopes; decrypts with KMS (Phase 3) or inside enclave (Phase 4) | Reads from `sync`, writes audit |
| `events` | Push notifications for approvals and alerts; WebSocket for dashboards | Redis/NATS |
| `scan` | GitHub secret-scanning partner endpoint; leak intake; auto-revoke | Postgres |

All services are Rust (axum), containerized, deployable with a single `docker compose` for self-hosting.

## Data flows

### F1. Self mode: SDK call through the local broker

```
App/SDK ──(1) POST http://127.0.0.1:7391/p/openai/v1/chat/completions
           Authorization: Bearer usk_h_9f3…                          ──▶ uskd
uskd  (2) reject if Origin/Sec-Fetch-* present; check Host
     (3) hash handle → lookup → {secret_id, policy, caller binding}
     (4) policy.evaluate(method, path, headers, caller, now) → allow | deny | approval_needed
     (5) decrypt secret (per-request), build upstream request:
         host = preset.upstream (api.openai.com), replace auth header
     (6) egress guard: scan body for other stored secrets → block if found
     (7) forward with TLS; stream response
     (8) scrub response chunks for any stored secret values
     (9) audit.append(use event) — before first response byte returned
     (10) return response to App
```

Latency budget: steps 2–6 and 9 < 1 ms typical; scrubbing streams uses Aho-Corasick with a rolling overlap of (max secret length − 1) bytes.

### F2. Template substitution

Request to `/p/generic` with header `X-Usk-Upstream: https://api.example.com` and body or headers containing `{{usk:example-key}}`. uskd substitutes only if `api.example.com` is in `example-key.upstreams`, else 403 `host_not_allowed`.

### F3. MCP `call_api`

```
Agent ─ tool call { secret:"stripe-live", method:"GET", path:"/v1/customers" } ─▶ uskd(mcp)
uskd: resolve secret by name for the MCP caller identity → synthesize internal request → F1 steps 4–9 → return scrubbed body (truncated to a size limit) + status
```

The agent's context receives: status, headers whitelist, body (scrubbed). Never the upstream request.

### F4. Unlock

```
User password ─▶ Argon2id ─▶ KEK ─▶ unwrap vault key (VK) ─▶ VK in mlocked memory
Passkey: WebAuthn PRF output ─▶ HKDF ─▶ KEK' ─▶ unwrap VK (second wrapping of the same VK)
```

### F5. Delegation (Phase 3)

```
Raj (owner)                         cloud                              Dev (grantee)
  │ create grant: secret, policy, expiry
  │ fetch broker public key (+ attestation in Phase 4), verify
  │ envelope = HPKE(broker_pk, {secret plaintext, policy, grant_id})
  │──── upload envelope + invite (single-use code) ──▶ sync
  │                                                     │◀── accept invite, register device pk ── Dev
  │◀── approve device? (push) ──────────────────────────│
  │──── approve ───────────────────────────────────────▶│──── handle usk_h_… ─────────────────▶ Dev
  │                                                     │
  │                                    Dev app ── signed request (device key) ──▶ broker-hosted
  │                                    broker: verify sig, load envelope, decrypt, F1 steps 4–9, upstream
  │◀── audit events (signed) ◀─────────── broker ───────────────────────────▶ Dev (copy)
```

Owner can rotate the underlying secret; the envelope is re-created; the handle stays the same.

### F6. Sync (Phase 3)

Each vault record is encrypted with the vault key before upload. The relay sees `{vault_id, record_id, version, ciphertext, nonce}`. Devices pull changes since their last version. Conflict → both versions kept, UI asks.

## Deployment modes

| Mode | Components | Who it is for |
|---|---|---|
| **Local** | uskd + CLI (+ desktop) | Everyone; Phase 1 default |
| **Local + cloud sync** | + accounts + sync | Multi-device users |
| **Hosted delegation** | + broker-hosted + events | Client/developer pairs |
| **Bring-your-own-broker** | broker-hosted image on the client's infra | Clients who will not trust our operator |
| **Self-hosted** | everything via docker compose / Helm | Companies |

## Failure behaviour

| Failure | Behaviour |
|---|---|
| uskd not running | SDK gets connection refused. `usk doctor` explains. Desktop app auto-starts uskd |
| Vault locked | 401 `vault_locked` with instructions; desktop shows unlock prompt |
| Policy deny | 403 with `{error:"policy_denied", rule:"…"}` never revealing the secret or full policy to non-owners |
| Approval timeout | 403 `approval_timeout` after 120 s |
| Upstream down | Upstream's error passed through, scrubbed |
| Hosted broker unreachable | Per-grant setting: fail-closed (default) or fail-open to a cached policy for N minutes (owner opt-in) |
| Audit write fails | Request denied (INV-4). Local disk full is surfaced loudly |

## Configuration

`~/.unseenkey/config.toml` (Windows: `%APPDATA%\Unseenkey\config.toml`):

```toml
[daemon]
listen = "127.0.0.1:7391"
idle_lock_minutes = 15
lock_on_sleep = true

[security]
argon2_profile = "desktop"   # desktop | light
allow_injection_default = false
require_peer_check = false   # enable executable allow-list on loopback

[cloud]
enabled = false
relay = "https://relay.unseenkey.dev"
```

No secret material ever appears in config.
