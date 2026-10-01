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

> **As built (2026-09-30):** the daemon is the `unseenkey-daemon` library, run in-process by `usk daemon run` (auto-spawned, detached, on first use) with `uskd` as a thin second binary from the same crate, so there is one executable to distribute. Runtime files `daemon.token` (0600), `daemon.addr`, `daemon.pid` live next to the vault; `USK_LISTEN` / `USK_IDLE_LOCK_MINUTES` override `config.toml`. Browser-origin rejection is tested with header-based requests and a raw-socket spoofed `Host`; the headless-browser (Playwright) variant moves to M1.5 hardening. Deferred: Unix socket / named pipe transport and sleep/screen-lock hooks (M2.2, where the desktop app has the platform hooks anyway). Windows gotcha: a spawned daemon inherits inheritable pipe handles, so the CLI clears the inherit flag on its std handles first (`usk::platform`, the crate's only `unsafe`).

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

> **As built (2026-10-01):** `core::handles` (hashed, `usk_h_` + 32 base62), `core::audit` (hash chain verifiable while locked; bodies encrypted under an audit DEK), `core::broker` (host lock with policy narrowing, adapters bearer/header/basic/query/template, Aho-Corasick scrubber over raw, base64, URL-encoded and JSON-escaped forms with a streaming overlap buffer), and the daemon's `/p/{preset}/…` route (reqwest + rustls with the `ring` provider, no redirects, HTTP/2, streamed responses scrubbed chunk by chunk, per-handle sliding-window counters, audit `use` written before the first byte and the request refused if the write fails). Every vault action now audits (unlock, lock, secret changes, reveal, handle create/revoke, policy change). CLI: `usk handle create|ls|show|revoke|policy`, `usk env`, `usk log`, `usk log verify`. Deferred to M1.5/M2: approval prompts (NeedsApproval currently returns 403 `approval_required`), caller identities beyond `local` (MCP tokens in M2.1), streaming request bodies (buffered to 32 MiB), camouflage handle formats (D-26), counters persisted every 100 uses and on lock. Test hook: `ServeOptions.upstream_overrides` maps logical hosts to a mock so the host lock is exercised with real host names. Real-API run done 2026-10-01: Claude Code (`claude -p`, Anthropic TypeScript SDK, OAuth bearer token from `claude setup-token`/credentials) pointed at the broker via `ANTHROPIC_BASE_URL` + `CLAUDE_CODE_OAUTH_TOKEN=usk_h_…` completed a `POST /v1/messages` with a 200 and the expected reply; the token was never displayed. Two findings fixed on the way: Node's `fetch` sends `sec-fetch-mode: cors` (removed from the browser markers; `Sec-Fetch-Site`/`Dest`/`User`, `Sec-CH-UA`, `Origin`, `Referer` remain), and bearer-kind secrets are injected as `Authorization: Bearer` regardless of the preset's key header (`sk-ant-oat…` detected as an OAuth bearer token; `usk env` emits `CLAUDE_CODE_OAUTH_TOKEN`). Still owed: the p99 overhead measurement.

### M1.5 `usk run`, `.env` guard, hardening (Weeks 8–9)
- Injection mode with output scrubbing; `allow_injection` gating.
- `.env` guard scan/fix.
- Memory hardening: mlock, per-request decrypt, no plaintext in errors/logs (redacting tracing layer).
- Threat-model test suite pass (INV-1…INV-8).
- Packaging: cargo-dist, Homebrew, winget, scoop; signed releases.

**Done:** Public alpha `v0.1.0`. 10 external users onboarded by hand.

> **As built (2026-10-01):** `usk run --with VAR=secret -- <cmd>` asks the daemon's `POST /v1/secrets/{ref}/inject` (refused unless the secret has `allow_injection`, every call audited as `inject` with the variable and command line), sets the variables on the child only, scrubs the child's stdout/stderr through the streaming scrubber, warns when the program is a shell, and exits with the child's code. `usk secret set <name> --allow-injection|--no-scrub|--notes|--tag|--upstream` edits the per-secret flags. `usk guard scan|fix [.env]` lists lines that look like secrets and, for providers with a preset, moves them into the vault (name from the key, uniquely suffixed), creates a handle, rewrites the line to the handle and adds/updates the provider's base-URL variable; secrets without a preset are left in place and reported. Hardening: `SecretBytes` buffers are `mlock`/`VirtualLock`ed best-effort (`crypto::platform`, the core's only `unsafe`, via `memsec`; the scrubber automaton still holds unlocked copies, see docs/04), and the daemon's log writer passes every line through the process-wide redactor so stored values can never reach `uskd.log` or stderr. Packaging: `.github/workflows/release.yml` builds `usk`/`uskd` for Linux x86_64/arm64, macOS arm64/x86_64 and Windows x86_64 on a `v*` tag, attaches SHA256SUMS, Sigstore keyless signatures and a CycloneDX SBOM to a draft GitHub release (untested until the first tag). Deferred: Homebrew/winget/scoop manifests (need a public repo), a Playwright browser test for INV-6, `.env` guard support for secrets without presets.

## Phase 2 — Agents and desktop (Weeks 10–17)

### M2.1 MCP server (Weeks 10–11)
- Tools, resources, prompts; stdio and streamable HTTP; per-client tokens and caller identity.
- `usk mcp install` for Claude Desktop, Claude Code, Cursor, Windsurf.
- Approval flow end-to-end in CLI (desktop prompt comes in M2.2).

**Done:** Claude Code can list secrets and call Stripe through `call_api`; a prompt-injection test (agent instructed to print the key) yields nothing.

> **As built (2026-10-01):** one implementation in the daemon (`POST /mcp`, Streamable HTTP with JSON responses; JSON-RPC methods `initialize`, `ping`, `tools/list|call`, `resources/list|read`, `prompts/list|get`); `usk mcp --client <name>` is a stdio bridge that forwards lines to it, so client configs hold only the command. Tools `list_secrets`, `call_api`, `request_access`, `explain_policy`, and `store_secret` (only with `[mcp] allow_store = true`); resources `usk://presets`, `usk://audit/recent` (this caller's events); prompt `setup-project`. Caller identity: `usk mcp install <client>` registers a `usk_m_` token (hash in `<vault dir>/mcp/clients.json`, plaintext in `<vault dir>/mcp/<client>.token`, 0600) and writes the client's config (Claude Code via `claude mcp add --scope user`; Claude Desktop, Cursor, Windsurf by merging `mcpServers.unseenkey` into their JSON). `call_api` auto-creates a handle per (client, secret) labelled `mcp:<client>/<secret>` with the provider's recommended policy and `callers = ["mcp:<client>"]`; owners tighten it with `usk handle policy`. The broker pipeline was split into `proxy::execute` (used by both the HTTP route and the tool) with two short vault-lock phases. **Approvals are live:** `NeedsApproval` parks the request (lock released) until `usk approve <id|latest> [--remember]` / `usk deny`, with the policy's timeout; `first_use` and `paths` decisions can be remembered per (handle, rule) until the daemon restarts; `request_access` pre-approves a gated rule or reports `denied_by_policy` when rules forbid it outright. Audit kinds added: `approval_decided`, `access_requested`. Deferred: desktop/mobile approval prompts (M2.2), server-initiated SSE on `/mcp`, persisting remembered decisions.

### M2.2 Desktop app (Weeks 12–15)
- Tauri shell managing uskd; onboarding (create vault, passkey, recovery kit); secrets list/detail; handle and policy editor with preset picker and plain-English explanation; approvals popup; audit viewer; tray status; `.env` guard UI; agent setup wizard.
- Passkey unlock via platform WebAuthn PRF (macOS/Windows), password fallback.
- Auto-updater with signed manifests; notarization and Authenticode.

**Done:** A new user goes from download to a working OpenAI call in Cursor in < 5 minutes without reading docs (tested with 5 people).

> **As built, slice 1 (2026-10-01):** `apps/desktop` is a Tauri 2 + React/TypeScript app kept outside the Cargo workspace (own lockfile; `cargo build --workspace` stays free of webkit/GTK) with its own CI job (`desktop.yml`, three OSes). The webview has no network permission: every action is a Tauri command in `src-tauri/src/lib.rs` that forwards to the daemon through `usk::client::Client` with the session token, so the UI reuses the CLI's routes and error codes. The app hosts the daemon itself when none is running: `Client::connect` re-executes the current binary as `--vault … daemon run --detached`, and the desktop binary recognises those arguments and runs `usk::daemon::run` instead of the UI, so a desktop install needs no separate `usk`. Screens: create vault (24 words shown once, acknowledged before continuing, daemon started and unlocked with the same password), unlock, secrets (add with provider detection and host lock, flags, audited 30-second reveal, delete), handles (policy cards from the preset with plain-English explanation, expiry, one-time handle + SDK environment in PowerShell/bash/.env form, revoke), approvals (daemon SSE pumped into Tauri events; system notification; window raised; Allow once / Allow always for this rule / Deny with a live countdown), activity (filter by kind, chain verification), agents (one-click MCP install for Claude Code, Claude Desktop, Cursor, Windsurf; shows last-seen), settings with the `.env` guard. Tray: Open, Lock vault, Quit; closing the window hides it. Deferred to slice 2: passkey unlock (WebAuthn PRF), signed auto-updater, notarization/Authenticode, sleep/screen-lock hooks, the five-person onboarding test (needs the public download).

> **As built, slice 2 (2026-10-01):** *Device unlock* per D-28: `core` gained `KeyWrap`s in the header (new SQLite table `key_wraps`, old vaults read as empty), `KekKind::Device(wrap_id)`, `Vault::add_key_wrap / remove_key_wrap / unlock_with_kek / key_wraps`; the daemon gained `/v1/unlock-methods` and the `wrap_id + kek` form of `/v1/unlock` (malformed bodies are refused before the attempt limiter), audit kinds `unlock_method_added/removed`, and `unlock` events now record the method. The desktop app implements Windows Hello in `src-tauri/src/hello.rs` (enable/disable in Settings while unlocked; the unlock screen prompts Hello once automatically and keeps the password field). Not verifiable headless: the Hello prompt needs a person, so the enrollment and unlock paths are exercised by the owner. *Lock on sleep and session lock:* `[daemon] lock_on_sleep` and `lock_on_session_lock` (both default true); the daemon's `platform.rs` (its only `unsafe`, crate moved from `forbid` to `deny(unsafe_code)`) runs a message-only window for `WM_WTSSESSION_CHANGE` and a `RegisterSuspendResumeNotification` callback for `PBT_APMSUSPEND`, and a portable resume detector locks after a wall-clock jump of more than 95 s in case the OS hook misses the suspend; `AppState::lock_vault(reason)` is the single lock path for the API, idle timer and hooks. *Signed updates:* `tauri-plugin-updater` with a minisign public key in `tauri.conf.json` and the endpoint `github.com/Bhagyesh97/unseenkey/releases/latest/download/latest.json`; a silent check at startup shows an "Install and restart" banner, and Settings has a manual check. The private key lives outside the repo (`~/.tauri/unseenkey.key`, generated without a password) and must be stored as the `TAURI_SIGNING_PRIVATE_KEY` repository secret; `release.yml` gained a `desktop` job (tauri-action on Windows, macOS arm64/x86_64, Ubuntu 22.04) that attaches installers and `latest.json` to the same draft release and signs with Apple or Authenticode certificates only when those secrets exist. Nothing in the release pipeline has run yet; it fires on the first `v*` tag after the repo goes public. Still owed: macOS Touch ID and Linux session hooks, the five-person onboarding test.

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
