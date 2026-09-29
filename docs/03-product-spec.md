# 03 — Product Specification

## Product statement

Unseenkey stores API keys, OAuth credentials, tokens, passwords and other secrets, and lets people, scripts and AI agents **use** them through a broker without ever receiving the plaintext. Owners attach **policies** to every use, can **delegate** use to other people or agents with expiry and revocation, and get a **tamper-evident audit log** of everything.

## Personas

| Persona | Name used in docs | Goal |
|---|---|---|
| Vibe coder | **Maya** | Build with AI tools without ever pasting a key into a chat or committing it |
| Client / business owner | **Raj** | Hire developers without handing over the keys to the business |
| Freelancer / agency developer | **Dev** | Get work done on Raj's accounts; not carry the liability of holding Raj's keys |
| AI agent | **Agent** | Call APIs on behalf of Maya or Dev without secrets in its context |

## Secret types supported

| Type | Examples | Use mechanism (Phase 1) |
|---|---|---|
| `api_key` | OpenAI, Anthropic, Stripe, SendGrid | Base-URL proxy, template |
| `bearer_token` | GitHub PAT, Slack bot token | Proxy, template |
| `basic_auth` | username + password for HTTP | Proxy (builds `Authorization: Basic`) |
| `oauth2_client` | client_id + client_secret + refresh token | Proxy with automatic token refresh (Phase 2) |
| `aws_credentials` | access key + secret + optional session token | SigV4 signing in broker (Phase 2); injection |
| `gcp_service_account` | JSON key file | Token exchange in broker (Phase 2); injection |
| `connection_string` | Postgres/MySQL/Redis URLs | Injection (Phase 1), protocol proxy (Phase 4) |
| `ssh_key` | private key | Injection via agent socket (Phase 4) |
| `password` | website logins | Store, reveal-with-approval only |
| `note` | any secret text, certificates | Store, reveal, injection |

## Feature list by phase

### Phase 1 — Self mode, local only (MVP core)

**Vault**
- Create vault protected by password (Argon2id) and optionally passkey (WebAuthn PRF).
- Add / edit / delete / tag / search secrets. Versions kept.
- Import from `.env`, 1Password/Bitwarden CSV export, plain paste with auto-detection of type and provider.
- Auto-lock on idle, on screen lock, on sleep.
- Recovery kit (words or file), printable.

**Broker (local daemon)**
- Loopback HTTP proxy with base-URL routes for provider presets and generic upstreams.
- `{{usk:name}}` template substitution with host lock.
- Handles: create, list, revoke, expire.
- Policy per handle: upstream, methods, path allow/deny, rate limit, total cap, expiry, approval mode.
- Streaming (SSE, chunked) passthrough.
- Egress guard and response scrubbing.
- Audit log (hash-chained SQLite) with CLI viewer.

**CLI (`usk`)**
- `usk init`, `usk unlock`, `usk add`, `usk ls`, `usk rm`, `usk handle create`, `usk policy edit`, `usk run`, `usk log`, `usk doctor`, `usk export` (encrypted).

**Provider presets**
OpenAI, Anthropic, Google AI, Mistral, Groq, OpenRouter, Stripe, GitHub, Supabase, Vercel, Resend, SendGrid, Twilio, Slack, Notion, Cloudflare. A preset = upstream host, auth header format, sensible default policies ("chat only", "read only").

### Phase 2 — Agents and desktop

- **MCP server** (stdio + streamable HTTP): `list_secrets`, `call_api`, `request_access`, `explain_policy`. Works with Claude Desktop/Code, Cursor, Windsurf, any MCP client.
- **Desktop app** (Tauri): vault UI, handle/policy editor, approval prompts, audit viewer, tray icon showing broker status.
- **Agent setup wizard**: one click writes MCP config for detected tools; one click prints the env vars for a project (`OPENAI_BASE_URL`, `OPENAI_API_KEY=usk_h_...`).
- Approval prompts (desktop notification with allow/deny).
- OAuth2 refresh, AWS SigV4, GCP token exchange in broker.
- `.env` guard: detect real keys in the project's `.env` and offer to move them into the vault and replace with handles.

### Phase 3 — Cloud: accounts, sync, delegation

- Account (email + passkey). End-to-end encrypted sync of the vault across devices.
- **Grants**: Raj selects secrets + policy + expiry, generates an invite. Dev accepts; Dev's device is registered as a caller.
- **Hosted broker** (KMS-backed, Rust, stateless, multi-region) for delegation mode.
- Bring-your-own-broker: one-command deploy to the client's Fly.io/Cloudflare/VPS.
- Owner dashboard: live usage, per-grant audit, revoke, pause, extend.
- Push approvals to phone (thin mobile app or PWA).
- Team workspaces: owner, admin, member; secrets shared within a workspace.
- GitHub secret-scanning partner registration for `usk_h_` handles; auto-revoke on report.

### Phase 4 — Advanced assurance

- Hosted broker in **attested enclaves** (AWS Nitro); client verifies attestation before encrypting a grant to the broker.
- **Rotation adapters** and scheduled rotation; one-click rotate after suspected leak.
- Leak monitoring for user-opted secrets (hash-based matching against public sources).
- Protocol-aware proxies: Postgres, MySQL, Redis, SSH agent.
- Spend accounting per provider (OpenAI usage headers, Stripe amounts) with spend caps.
- SOC 2 Type II, third-party audit report published.
- Self-hosted enterprise package (Helm chart), SSO/SCIM.

## User stories with acceptance criteria

### Maya (self mode)

**S1.** *As Maya, I want to give Cursor my OpenAI key without the key being in any file or chat.*
- `usk add openai` accepts a pasted key, detects the provider, stores it.
- `usk handle create openai --preset chat` prints `OPENAI_BASE_URL` and `OPENAI_API_KEY=usk_h_...`.
- The OpenAI SDK works unchanged with these variables, including streaming.
- Grepping the project, shell history and Cursor config for `sk-` finds nothing.

**S2.** *As Maya, I want to know if my agent tries to send a key somewhere it should not.*
- An agent request containing a stored secret's plaintext to a non-upstream host is blocked with HTTP 403 and an audit event `egress_blocked`, and a desktop notification appears.

**S3.** *As Maya, I want a leaked handle to be harmless.*
- A `usk_h_` token pasted publicly cannot be used from any machine that is not a registered caller. Revoking takes one command and takes effect immediately.

**S4.** *As Maya, I want to keep working when offline.*
- All Phase 1 and 2 features function with no network access.

### Raj and Dev (delegation mode)

**S5.** *As Raj, I want to let Dev build against my Stripe account without giving Dev the key.*
- Raj creates a grant: secret `stripe-live`, preset "Stripe: payments, no refunds, no payouts", expires in 30 days, approval on `POST /v1/transfers`.
- Dev accepts an invite link, registers their device, receives a handle.
- Dev's SDK calls succeed through the hosted broker; Dev cannot obtain the plaintext through any API, log or error message.
- Raj's dashboard shows each call within 5 seconds.

**S6.** *As Raj, I want to end access instantly.*
- Revoke takes effect within 1 second on the hosted broker; subsequent calls receive 403 with a clear message.

**S7.** *As Dev, I want to prove I never held the key.*
- Dev can export the signed audit log for the grant showing only proxied usage and no reveal events.

### Agent

**S8.** *As an Agent, I want to call APIs by name.*
- `call_api(secret="stripe-live", method="GET", path="/v1/customers?limit=3")` returns the scrubbed response. `list_secrets` returns names, types, providers and policy summaries, never values.

## Non-functional requirements

| Area | Requirement |
|---|---|
| Latency | Local broker adds < 2 ms p50, < 10 ms p99 (excluding upstream). Hosted broker adds < 30 ms p50 within region |
| Throughput | Local: 2,000 req/s on a laptop. Hosted: horizontally scalable, stateless |
| Availability (hosted) | 99.9% Phase 3, 99.95% Phase 4; per-customer fail-closed default |
| Memory hygiene | Plaintext zeroized after use; vault key never written to disk unencrypted; `mlock` where available |
| Binary size | CLI/daemon < 25 MB; desktop app < 40 MB installer |
| Platforms | macOS (Apple Silicon + Intel), Windows 10+, Linux (x86_64, arm64). Web app (Phase 3) evergreen browsers |
| Accessibility | Desktop UI keyboard-navigable, screen-reader labels, WCAG 2.1 AA contrast |
| Privacy | No telemetry by default; opt-in crash reports with secrets scrubbed |

## Success metrics

- Phase 1: 1,000 CLI installs, 100 weekly-active vaults, NPS from 30 interviews > 40.
- Phase 2: 40% of active users have an MCP client configured; median "time to first proxied call" < 5 minutes.
- Phase 3: 200 grants created; 20 paying client/developer pairs; zero plaintext-exposure incidents.
- Phase 4: external audit with no critical findings; first enterprise self-hosted deployment.
