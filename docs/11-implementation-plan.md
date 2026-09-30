# 11 — Implementation Plan

Assumes one experienced developer full-time (with AI assistance), or a two-person team halving the calendar. Weeks are estimates; each milestone has a demo and a "done" definition. Security tests from [12](12-testing-and-assurance.md) are part of "done", not a later phase.

> **Order of execution (D-27, 2026-09-30):** Phase 0 → Phase 1 → M2.1 (MCP) → **M3.1 + M3.2 as "delegation-lite"** (web dashboard instead of desktop; CLI for grantees) → M2.2 desktop app, M2.3 adapters, transparent mode, importers → Phase 3 remainder → Phase 4. The phase numbering below is kept for reference; the sequence above is what we build. Ten customer conversations gate the delegation build.

## Phase 0 — Foundations (Week 1)

- Monorepo, workspace, CI matrix (macOS/Windows/Linux/wasm32), `cargo deny`/`audit`, formatting and clippy gates.
- `SecretBytes` type with zeroize, redacted Debug/Display, and a compile-fail test that it cannot be JSON-serialized.
- `crypto` module: Argon2id, HKDF, XChaCha20-Poly1305, BLAKE3, Ed25519, HPKE wrappers; test vectors generated and committed.
- `SECURITY.md`, licences, `CONTRIBUTING.md`.

**Done:** CI green on all targets; test vectors pass natively and in WASM.

## Phase 1 — Self mode, local (Weeks 2–9)

### M1.1 Vault and CLI basics (Weeks 2–3)
- `storage` trait + SQLite backend; `vault` records, versions, tombstones; header and key wrapping; unlock/lock.
- `usk init`, `unlock`, `lock`, `add`, `ls`, `show`, `rm`, `reveal`, `export`, `import` (`.env`, CSV/JSON of 1Password/Bitwarden).
- Recovery kit generation and restore.
- Provider detection from pasted values.

**Done:** Round-trip 1,000 secrets; vault file contains no plaintext (test greps ciphertext for known values); restore from recovery words works.

### M1.2 Daemon and management API (Week 4)
- `uskd` with axum; session token file; Unix socket / named pipe; `/v1/*` routes; SSE events.
- Ingress guard (Origin/Sec-Fetch/Host) with tests.
- Auto-lock on idle; lock on sleep/screen-lock hooks per platform.
- `usk doctor`.

**Done:** Malicious-page test (a headless browser hitting localhost) gets 403 on every route; peer-token test passes.

### M1.3 Policy engine (Week 5)
- Schema parse/validate, glob matcher, limits, schedule, approval modes, `explain` renderer.
- Presets for 17 providers with default policies.
- Property tests and fuzzing harness for the evaluator.

**Done:** 100% branch coverage on `eval.rs`; fuzz 1 h without panic; explanations reviewed for all presets.

### M1.4 Broker pipeline (Weeks 6–7)
- Handle creation/lookup (hashed, constant-time), caller binding.
- Adapters: bearer, header, basic, query, template.
- Host lock, egress guard, scrubber (with streaming overlap), forwarder with rustls and HTTP/2, streaming SSE.
- Audit log with hash chain; `usk log`, `usk log verify`.
- `usk handle`, `usk env`, `usk policy` commands.

**Done:** OpenAI, Anthropic and Stripe official SDKs work unchanged via env vars (integration tests against mock upstream + one manual run against real APIs); streaming works; egress-block and scrub tests pass; p99 overhead < 10 ms on the mock.

### M1.5 `usk run`, `.env` guard, hardening (Weeks 8–9)
- Injection mode with output scrubbing; `allow_injection` gating.
- `.env` guard scan/fix.
- Memory hardening: mlock, per-request decrypt, no plaintext in errors/logs (redacting tracing layer).
- Threat-model test suite pass (INV-1…INV-8).
- Packaging: cargo-dist, Homebrew, winget, scoop; signed releases.

**Done:** Public alpha `v0.1.0`. 10 external users onboarded by hand.

## Phase 2 — Agents and desktop (Weeks 10–17)

### M2.1 MCP server (Weeks 10–11)
- Tools, resources, prompts; stdio and streamable HTTP; per-client tokens and caller identity.
- `usk mcp install` for Claude Desktop, Claude Code, Cursor, Windsurf.
- Approval flow end-to-end in CLI (desktop prompt comes in M2.2).

**Done:** Claude Code can list secrets and call Stripe through `call_api`; a prompt-injection test (agent instructed to print the key) yields nothing.

### M2.2 Desktop app (Weeks 12–15)
- Tauri shell managing uskd; onboarding (create vault, passkey, recovery kit); secrets list/detail; handle and policy editor with preset picker and plain-English explanation; approvals popup; audit viewer; tray status; `.env` guard UI; agent setup wizard.
- Passkey unlock via platform WebAuthn PRF (macOS/Windows), password fallback.
- Auto-updater with signed manifests; notarization and Authenticode.

**Done:** A new user goes from download to a working OpenAI call in Cursor in < 5 minutes without reading docs (tested with 5 people).

### M2.3 Provider adapters (Weeks 16–17)
- AWS SigV4, OAuth2 refresh, GCP service-account token exchange.
- More presets (community contributions via `presets/`).
- Transparent mode with per-session ephemeral CA (D-23); tests: CA never in OS store, deleted on exit, non-upstream hosts tunnelled untouched.
- Importers: OS keychain, 1Password, Bitwarden, Infisical Agent Vault, OneCLI, Veil, `pass` (D-24).
- Agent-framework plugins: OpenClaw, NanoClaw, Hermes; one-line setup for Codex (D-25).
- Camouflage handle formats per preset (D-26).
- Optional dedicated-OS-user broker with peer-credential checks, Linux and Windows (D-24).

**Gate before Phase 3:** delegation interviews with five agencies and five freelancers (D-25).

**Done:** `v0.5.0` public beta; launch post; collect the 30 interviews.

## Phase 3 — Cloud: accounts, sync, delegation (Weeks 18–29)

### M3.1 Accounts and sync (Weeks 18–21)
- `cloud-accounts` (passkeys, devices), `cloud-sync` (ciphertext records, versions, conflicts), client `sync` module, `usk cloud *`.
- Web app skeleton (WASM core, unlock, list, dashboards).
- docker-compose for self-hosting.

**Done:** Two devices stay in sync with conflicts surfaced; relay database inspection reveals no names or values.

### M3.2 Delegation and hosted broker (Weeks 22–26)
- `grants` module, invites, device registration with owner approval, envelopes to the broker key (KMS-backed).
- `cloud-broker`: signed-request verification, envelope decrypt, shared pipeline, audit signing, revoke propagation (< 1 s via pub/sub), fail-closed/open per grant.
- Local uskd relay mode for grantees' SDKs.
- Owner dashboard: live usage, revoke/pause/extend; grantee view with exportable signed log.
- `cloud-events`: push approvals to desktop and PWA.

**Done:** Raj/Dev scenario S5–S7 passes end-to-end in staging; revoke measured < 1 s; penetration test by an external firm on the hosted broker.

### M3.3 Trust and growth (Weeks 27–29)
- GitHub secret-scanning partner registration; `cloud-scan` auto-revoke.
- Workspaces (owner/admin/member).
- Billing (Stripe, naturally through Unseenkey), pricing tiers.
- Bug bounty (private).

**Done:** `v1.0.0`. Public launch.

## Phase 4 — Advanced assurance (Weeks 30+)

- Nitro Enclave broker image, reproducible build, attestation verification in clients, published PCR list.
- Rotation adapters (OpenAI, Anthropic, Stripe, AWS IAM, GitHub, GCP) and schedules.
- Leak monitoring (hash-based) for opted-in raw keys.
- Protocol proxies: Postgres, MySQL, Redis; SSH agent.
- Spend accounting and caps.
- SOC 2 Type II; third-party crypto audit; publish report.
- Helm chart, SSO/SCIM for self-hosted enterprise.

## Suggested order of first commits (Phase 0/1 kickoff)

1. `cargo new` workspace; `crates/core` with `crypto::secret_bytes` + tests.
2. `crypto::kdf`, `crypto::aead`, vectors.
3. `storage::trait` + `storage::memory` + `storage::sqlite`.
4. `vault::header` (create/unlock) → `vault::records` (put/get/list) → `usk init/add/ls`.
5. `policy::schema` + `policy::eval` + presets.
6. `handles` → `broker::pipeline` with `bearer` adapter against mock upstream → `usk env`.
7. `broker::scrub` + `broker::egress` → `audit` → `usk log`.
8. `uskd` ingress guard + management API → `usk` switches to talking to `uskd`.

Each step is independently testable and demo-able.

## Risks to the plan

| Risk | Mitigation |
|---|---|
| Passkey PRF support uneven across platforms | Password path first; PRF behind feature detection; document support matrix |
| MCP spec churn | Keep `mcp` module thin; adapt via the official SDK |
| SDKs that ignore `base_url` or pin hosts | Presets flag them; fall back to template/injection; maintain a compatibility list |
| Solo-dev burnout | Cut scope, not security tests; Phase 3 can be delayed, Phase 1–2 alone is a product |
| Trust bootstrap | Open source from the first commit; publish threat model; local mode needs no trust |
