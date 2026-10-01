# 02 — Brainstorm and Decisions

This is the record of the design brainstorm. Each item states the question, the options considered, the decision and the reasoning. Treat entries as Architecture Decision Records: if a decision changes, add a new entry that supersedes it rather than editing history.

Legend: **D-nn** = decision. **Open** = intentionally left open with a default.

---

## D-01 Name

**History:** The working codename was "Blindkey". Availability checks on 2026-09-30 found it already in use by a same-concept project ([michaelkenealy/blindkey](https://github.com/michaelkenealy/blindkey), Feb 2026, MIT, TypeScript, npm scope `@blindkey`, "makes AI agents blind to your API keys") and `blindkey.com` registered since 2007. "Veilkey" and "Blindvault" were also taken by similar agent-secrets projects.

**Options checked (npm, crates.io, PyPI, GitHub org, .com/.dev/.app):** Unseenkey (all free, incl. .com), Keyshroud (all free except .com), Sealkey, Hushkey (registries free, org and .com taken).
**Decision:** **Unseenkey**. Says exactly what the product does, clean on every registry and domain checked, GitHub org free.
**Conventions:** CLI `usk`, daemon `uskd`, token prefixes `usk_h_` / `usk_s_` / `usk_m_` / `usk_i_` (handle regex `usk_h_[A-Za-z0-9]{32}`), template `{{usk:name}}`, headers `X-Usk-*`, data dir `~/.unseenkey/`, crate `unseenkey-core`, repo `unseenkey`.
**To do (owner):** register `unseenkey.com`, `.dev`, `.app`; reserve the GitHub org `unseenkey`, npm package `unseenkey` and scope `@unseenkey`, crates.io `unseenkey` and `unseenkey-core`, PyPI `unseenkey`; run a trademark search before public launch.

## D-02 First customer

**Options:** (a) enterprises, (b) AI-agent platforms, (c) vibe coders + freelancer/client pairs.
**Decision:** (c), with (b) as distribution channel.
**Why:** Enterprises need SOC 2, SSO, procurement and 9-month cycles, and incumbents own them. Vibe coders are numerous, loud on social media, and the pain is acute and visible (surprise bills). The client/developer pair is the only segment where nobody offers a product and where willingness to pay is emotional (fear of fraud). Agents are how the product enters every workflow.

## D-03 Two trust modes

**Question:** Is "the broker holds the key and injects it" enough?
**Analysis:** It depends on who controls the broker.
- If the *user of the key* controls the broker (self mode), they can read its memory; that is fine because they own the key anyway. The goal is preventing *accidental* leaks.
- If the *user of the key* is not the owner (delegation mode), the broker must be outside their control, or "never sees the key" is a lie.

**Decision:** Design and document the two modes separately. Self mode ships first (local broker). Delegation mode requires a broker the developer cannot inspect: hosted broker (Phase 3), then attested enclave (Phase 4), plus "bring your own broker" for clients who can run a server.

## D-04 Local-first vs cloud-first

**Options:** (a) SaaS first, (b) local-first with optional cloud, (c) local only.
**Decision:** (b).
**Why:** Local-first means no honeypot on day one, no trust needed to try it, works offline and in air-gapped setups. Cloud is needed for sync, delegation and hosted broker, so it cannot be excluded. (a) would require us to be trusted before we have earned it.

## D-05 How SDKs use a secret without the secret

**Options:**
1. **Base-URL swap + handle as API key.** `OPENAI_BASE_URL=http://127.0.0.1:7391/p/openai/v1`, `OPENAI_API_KEY=usk_h_...`. Broker rewrites the auth header and forwards to the real upstream.
2. **Placeholder templates.** `{{usk:stripe-live}}` anywhere in URL, headers or body; broker substitutes.
3. **Forward proxy (HTTP CONNECT / MITM).** Transparent but requires installing a CA certificate; fragile with pinning; heavy.
4. **Env injection.** `usk run -- cmd`; the process gets plaintext.

**Decision:** 1 and 2 are the primary mechanisms. 4 is supported as an explicitly weaker "injection mode" (off by default per secret). 3 is rejected: CA installation is a bigger attack surface than the problem it solves. *(Partly superseded by D-23: an opt-in transparent mode with an ephemeral, non-installed CA.)*

## D-06 Handles will leak; make them worthless

**Analysis:** People will paste `usk_h_...` into chats exactly as they paste `sk-...` today. The design must assume the handle is public.
**Decision:** A handle alone cannot use a secret. The broker additionally requires: (a) the request arrives from a registered **caller** (local: loopback + daemon session; remote: device key / mTLS / signed request), (b) the handle's policy allows the request, (c) the handle is not expired or revoked. Handles have a fixed format `usk_h_[A-Za-z0-9]{32}` so secret scanners (GitHub partner program, gitleaks rule) can detect them; a detected leak auto-revokes the handle. Marketing line: *leaks become harmless*.

## D-07 Preventing a web page from talking to the local broker

**Analysis:** Any website can issue `fetch("http://127.0.0.1:7391/...")`. DNS rebinding makes `Host` checks alone insufficient.
**Decision:** The local broker rejects any request that carries `Origin`, `Referer` or `Sec-Fetch-*` headers (browsers always send at least `Sec-Fetch-Mode`), rejects unexpected `Host` values, sends no CORS headers, and requires a per-session bearer token (`~/.unseenkey/daemon.token`, mode 0600) for management routes. Proxy routes are authenticated by the handle plus these checks.

## D-08 Secret injection must be host-locked

**Analysis:** If `{{usk:openai}}` can be substituted into a request to `evil.com`, an agent under prompt injection can exfiltrate every secret in one call.
**Decision:** Every secret carries an `upstream` allow-list. Substitution happens only if the destination host matches. Base-URL routes are inherently locked because the route defines the upstream. There is no "any host" option; a wildcard must be explicit and produces a warning in the UI.

## D-09 Egress and response scrubbing (built-in DLP)

**Decision:** The broker scans outgoing request bodies for plaintext values of *any* stored secret going to a host that is not that secret's upstream: block and alert. It scans responses (including streamed chunks, with overlap buffering) for stored secret values and replaces them with `[REDACTED:usk:<name>]`. This is what makes an MCP tool call safe even when an API echoes credentials back.

## D-10 Env injection stays but is fenced

**Analysis:** DB connection strings, SSH keys, SDKs that pin hosts, and CLIs cannot be proxied. Env injection gives the process plaintext; the agent that launched the process could read it (e.g. `echo $KEY`).
**Decision:** Keep `usk run`. Per-secret flag `allow_injection` default off. Command output is scrubbed. Documented in the threat model as residual risk. Later: protocol-aware local proxies for Postgres/MySQL/Redis (the broker completes the auth handshake, the app connects to localhost without credentials).

## D-11 Policy language

**Options:** (a) custom DSL, (b) OPA/Rego, (c) Cedar, (d) plain structured YAML/JSON with a fixed schema.
**Decision:** (d). A fixed schema is auditable by non-experts (the client must understand what they granted). Cedar is a reasonable upgrade path if expressiveness runs out; noted as Open-2.
**Amendment (2026-09-30, M1.3):** the human-edited form is **TOML**, not YAML, and the stored form is JSON, same schema. Reason: the standard `serde_yaml` crate is unmaintained (RUSTSEC advisory) and its forks are not established; `toml` is already a dependency. Unknown fields are rejected on parse (INV-5).

## D-12 Approval flows

**Decision:** Policies support `approval: none | first_use | every_use | paths: [...]`. Approval requests are delivered to the owner's desktop app or phone (push via cloud relay in Phase 3). Timeout default 120 s, then deny. In self mode this is also useful: "your agent wants to use AWS-prod, allow?"

## D-13 Cryptography choices

**Decision:** Argon2id (m=256 MiB, t=3, p=1 desktop; lighter profile on mobile/web) for password-derived keys. XChaCha20-Poly1305 for data. HKDF-SHA256 for derivation. BLAKE3 for hashing. X25519 HPKE for sharing in v1 with a versioned envelope; ML-KEM-768 + X25519 hybrid as envelope v2 once a vetted Rust implementation is adopted. WebAuthn with the PRF extension for passkey unlock; OS keychain fallback. No custom primitives. Details in [06](06-cryptography.md).

## D-14 Zero-knowledge vs. the broker

**Analysis:** Zero-knowledge storage and a hosted broker that injects plaintext are in tension: the broker must decrypt.
**Decision:** Self mode is fully zero-knowledge to the cloud (cloud stores ciphertext only). In delegation mode the owner explicitly encrypts a grant *to the broker's public key*. In Phase 3 that key lives in a KMS-backed service (owner trusts the operator). In Phase 4 the key lives inside an attested enclave, and the owner's client verifies the attestation before encrypting. The UI must show which of these the user is trusting. No hiding it.

## D-15 Language and stack

**Options:** (a) TypeScript everywhere, (b) Rust core + TypeScript UI, (c) Go core + TypeScript UI.
**Decision:** (b).
**Why:** Memory safety for code that holds plaintext, a single small signed binary for the daemon/CLI, compiles to WASM for the browser so the same audited crypto runs everywhere, and strong crypto crates (RustCrypto, ring, libcrux). (a) is faster to write but a Node process holding secrets and a 200 MB dependency tree does not earn trust. (c) is fine but the WASM story and crypto ecosystem are weaker.

## D-16 Desktop shell

**Options:** Electron, Tauri 2, native per-OS.
**Decision:** Tauri 2. Rust backend is the same crate as the daemon; tiny binary; system webview. Mobile via Tauri 2 mobile later for approvals only.

## D-17 Open source

**Decision:** Core library, CLI, daemon, desktop app, MCP server: Apache-2.0. Cloud services (relay, sync, hosted broker, accounts): AGPL-3.0, self-hostable. Reason: trust requires inspection; AGPL prevents a cloud vendor from offering our service without contributing.

## D-18 Sync and conflicts

**Options:** CRDT, per-record versioning with last-writer-wins, full-vault blob.
**Decision:** Per-record versioning with LWW and conflict copies. Secrets are rarely edited concurrently; CRDTs are complexity we do not need.

## D-19 Audit log integrity

**Decision:** Append-only, each event includes BLAKE3 of the previous event (hash chain). Local: SQLite. Delegation: broker signs each event with its key; owner and grantee both receive copies; a client can detect tampering by re-hashing. Periodic checkpoints anchored to the cloud (Phase 3).

## D-20 Rotation and leak monitoring

**Decision:** Phase 4. Provider adapters for OpenAI, Anthropic, Stripe, AWS IAM, GitHub, Google service accounts. Leak monitoring via GitHub secret-scanning partner program (for handles) and public-paste monitoring (for raw keys the user opted to watch, using hashes only).

## D-21 What is *not* in MVP

SSO/SCIM, browser autofill, HSM, Kubernetes operator, WebSocket proxying, spend accounting, mobile app, team RBAC beyond owner/grantee, Windows credential-provider integration, secret *generation* for passwords (basic generator only).

## D-22 The "power problem" is a product feature, not a footnote

**Decision:** Endpoint-level allow/deny, request caps and approvals are first-class in the grant UI, with provider presets ("Stripe: read-only", "OpenAI: chat only, no fine-tuning, no billing"). Without this, delegation protects the string but not the money.

---

## Decisions from competitive research (2026-09-30, see [16](16-competitive-research.md))

## D-23 Opt-in transparent proxy mode (partly supersedes D-05)

**Context:** Infisical Agent Vault, OneCLI and Veil all use an HTTPS MITM proxy because CLIs such as `gh`, `git`, `aws` and `gcloud` ignore base-URL variables. nono offers it as an option. A reverse proxy alone leaves those tools uncovered.
**Decision:** Add `usk run --transparent -- <cmd>` in Phase 2. It generates a **per-session CA** in memory, writes a temporary bundle (system roots + session CA) to a session directory, and points only the child process at it via `HTTPS_PROXY`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`. The CA is never installed in the OS trust store, is deleted when the session ends, and signs only for hosts that appear in some secret's `upstreams`; every other CONNECT is tunnelled untouched. Injection rules are the same as the reverse proxy (host lock, policy, egress guard, scrubbing, audit). Default remains the reverse proxy; the UI explains the trade-off. Not offered for delegation mode (the grantee controls the machine anyway; they use the local relay).

## D-24 Interoperability: sources, importers, sandboxes

**Decision:**
- **Importers** (Phase 2): OS keychain, 1Password (`op` CLI), Bitwarden (`bw` / `bws`), Infisical Agent Vault, OneCLI, Veil and `pass`, in addition to `.env` and CSV/JSON exports.
- **Unseenkey as a credential source** (Phase 3): expose a `usk://<name>` resolver and a small local endpoint so nono, OneCLI and similar proxies can fetch a *session-scoped handle* (never the plaintext) from Unseenkey; document the nono profile.
- **Sandbox stance:** we do not build a kernel sandbox. For the "hostile agent with code execution" threat the docs recommend nono (or OS-level isolation) and `usk` integrates with it.
- **Optional broker isolation** (Phase 2, Linux/Windows): run `uskd` as a dedicated OS user with peer-credential checks on the socket, as BlindVault does, so a same-user agent cannot read broker memory. Off by default; one-command setup.

## D-25 Positioning and roadmap shifts

**Context:** "Agent uses the key but never sees it" is now offered by ten projects; three are well funded. Delegation, owner-first UX, assurance and Windows are uncontested.
**Decision:**
- Lead with delegation ("hire a developer without handing over your keys") and leak-harmless handles; the agent proxy becomes a proof point.
- Windows is a first-class target from Phase 1 (CI, installer, keychain via DPAPI, named pipes), not a port.
- Agent-framework plugins and one-line setup for OpenClaw, NanoClaw, Hermes, Claude Code, Cursor, Codex and Windsurf move from Phase 4 to Phase 2.
- Delegation user research (five agencies, five freelancers) is a gate before Phase 3 starts.

## D-26 Camouflage handles

**Context:** Some SDKs validate key shape (prefix or length) before sending. Veil avoids this with realistic-looking placeholders.
**Decision:** Each preset may define a `handle_format` (e.g. OpenAI `sk-usk-<32 chars>`, Stripe `sk_live_usk_<24 chars>`). `usk handle create` uses the preset format when the preset declares it is needed; otherwise the canonical `usk_h_` form. All formats contain the `usk` marker, are registered with secret scanners, and are looked up by hash exactly like canonical handles. The canonical form remains the default.

## D-27 Re-ordered roadmap: delegation before desktop

**Context:** Delegation is the only uncontested and only unvalidated part of the product, and the original plan reached it in week 22.
**Decision (approved 2026-09-30):** Weeks 1–8 Phase 0 + Phase 1 (core, vault, local broker, CLI). Weeks 9–10 MCP server only. Weeks 11–18 **delegation-lite**: accounts, grants, invites, KMS-backed hosted broker, a simple web dashboard for owners (developers use the CLI). Week 19+ desktop app, transparent mode, importers, then Phase 4 assurance. Ten customer conversations (five agencies/freelancers, five clients) happen before week 11 and gate the hosted build. Repo is private until the Phase 1 alpha, then public with the threat model as README. Details in [11](11-implementation-plan.md).

## D-28 Device unlock through native credentials, not WebAuthn PRF

**Context:** M2.2 planned passkey unlock via WebAuthn PRF in the webview. WebView2 only exposes the PRF extension for some authenticators, WKWebView has no WebAuthn at all without a browser entitlement, and a `tauri dev` origin is an IP address, which WebAuthn refuses. None of that is fixable from our side.
**Decision (2026-10-01):** The vault header carries zero or more *device wraps*: the vault key wrapped under a 32-byte KEK that a platform credential derives on demand. Windows uses Windows Hello (`KeyCredentialManager`: a TPM-backed key pair per vault; `KEK = HKDF(sign(salt), "usk/kek/hello/v1")`, deterministic because the signature is RSA PKCS#1 v1.5). Each wrap has its own id bound into the AAD, a public 32-byte salt, and is enrolled or removed only while the vault is unlocked. The password and recovery phrase stay; a device wrap is a convenience that is exactly as strong as the OS credential. macOS (Touch ID through the Secure Enclave) and Linux follow the same shape when they land. The daemon speaks `GET/POST/DELETE /v1/unlock-methods` and `POST /v1/unlock { wrap_id, kek }`; the desktop app is the only caller today.

## Open items (defaults chosen; revisit when data arrives)

- **Open-1: Pricing tiers.** Default in [15](15-business-and-gtm.md). Validate with 20 customer conversations.
- **Open-2: Policy language upgrade.** Cedar if the fixed schema proves insufficient.
- **Open-3: Enclave provider.** AWS Nitro Enclaves default; alternatives Intel TDX on GCP, AMD SEV-SNP on Azure.
- **Open-4: ML-KEM hybrid timing.** Adopt when `libcrux` or RustCrypto `ml-kem` reaches a version we consider stable and audited.
- **Open-5: Mobile approvals.** Tauri mobile vs. a thin native app. Decide when Phase 3 starts.

## Ideas considered and dropped

- Browser extension that intercepts key fields on provider dashboards: nice, but a different product (password manager); revisit after PMF.
- Blockchain anchoring for the audit log: no user asked for it; a public transparency log (like Sigstore Rekor) is the sober version if ever needed.
- Selling "rotation as a service" alone: useful, but incumbents (GitGuardian) will add it; not a wedge.
- Custom LLM to classify secrets: regex + provider prefixes cover 95%; not worth the risk of sending secrets to a model.
