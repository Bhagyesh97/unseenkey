# Unseenkey

**Let AI agents, scripts and the people you hire *use* your API keys without ever *seeing* them.**

Unseenkey keeps your keys in an encrypted vault on your machine and hands out **handles** instead. A handle looks like a key to the SDK that receives it, but it only works through the local **broker**, which swaps it for the real key at the last moment, checks a **policy** (which host, which endpoints, how often, until when, with whose approval), scrubs the real key out of the response and writes every call to a tamper-evident **audit log**. Paste a handle into a chat, commit it to git, give it to a contractor: nothing happens, and you can revoke it with one command.

> **Status: alpha (v0.1).** The local vault, broker, CLI, MCP server and desktop app work and are tested on Windows, macOS and Linux. No external security audit has happened yet; use it with keys you can rotate. Delegation to other people through a hosted broker is designed ([docs/](docs/00-README.md)) but not built.

## Two minutes with Claude Code

```
usk init                                  # pick a password; write down the 24 recovery words
usk add anthropic                         # paste the key at a hidden prompt; provider detected, host-locked
usk env anthropic --policy chat           # prints ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY=usk_h_…
claude -p "hello"                         # Claude Code now calls Anthropic through the broker
usk log                                   # every call, hash-chained
```

`--shell powershell|cmd|dotenv` prints the variables in the form your shell or `.env` file wants. The daemon starts itself on first use, locks after 15 idle minutes and whenever the screen locks or the machine sleeps, and listens on loopback only.

More of the same:

```
usk guard fix .env                        # replace the real keys in a .env with handles (originals go in the vault)
usk mcp install claude-code               # or claude-desktop, cursor, windsurf: the agent gets tools, never values
usk add aws-dev && usk env aws-dev        # boto3, the AWS CLI and the JS SDK sign with a placeholder; the broker re-signs with the real key
usk add google-oauth                      # paste a refresh token or gcloud's ADC file; the broker keeps the access token fresh
usk handle create stripe --policy payments --expires-days 7   # for a contractor: payments yes, refunds and payouts no, gone next week
usk run --with DATABASE_URL=prod-db -- ./app   # for things that cannot be proxied (the program sees the value; audited and scrubbed)
```

## Install

Pre-built binaries and desktop installers are on the [Releases](https://github.com/Bhagyesh97/unseenkey/releases) page: `usk-<version>-<target>.{zip,tar.gz}` for the CLI (Windows x64, macOS arm64/x64, Linux x64/arm64), plus NSIS/MSI, DMG and deb/rpm/AppImage for the desktop app. Every archive has a Sigstore signature, every installer a minisign signature, and each release ships an SBOM.

From source, with stable Rust 1.85 or newer:

```
cargo install --locked --git https://github.com/Bhagyesh97/unseenkey usk
```

The desktop app is a thin window over the same daemon (unlock, approvals, audit viewer, one-click MCP setup, Windows Hello unlock, signed auto-updates); see [apps/desktop](apps/desktop/README.md).

## How it works

```
 your SDK / agent / contractor                    the broker (uskd, 127.0.0.1 only)                 the provider
 ──────────────────────────────                   ─────────────────────────────────────────────     ────────────
 Authorization: Bearer usk_h_7Qx…   ──────────►   handle → secret (vault, decrypted per request)
 ANTHROPIC_BASE_URL=http://127.0.0.1:7391/p/anthropic   policy: host, path, method, rate, expiry, approval
                                                  audit entry written before the first byte leaves   ──────────►  api.anthropic.com
                                    ◄──────────   response scrubbed of anything that looks like the key  ◄──────────
```

- **Vault:** Argon2id → XChaCha20-Poly1305, one SQLite file, keys mlocked in memory and zeroised on lock; a 24-word recovery phrase; optional Windows Hello unlock.
- **Handles:** `usk_h_…` by default, or *camouflage* handles that pass the SDK's own format checks (`sk-proj-usk-…`, `sk_live_usk…`); every format carries the `usk` marker so secret scanners can learn it.
- **Policy:** per-provider presets with plain-English `usk policy explain`; approvals in the desktop app or `usk approve`; "allow always" rules you can forget later.
- **Fail closed:** each secret is locked to its provider's hosts, unmatched requests are refused, requests that come from a browser are refused, anything the broker cannot classify is refused.
- **Audit:** hash-chained log with `usk log verify`; the entry is committed before the upstream request is sent.
- **Providers:** Anthropic, OpenAI, Google AI, Groq, Mistral, OpenRouter, GitHub, Stripe, Slack, Notion, Cloudflare, Vercel, Supabase, Twilio, SendGrid, Resend, AWS (SigV4 re-signing), OAuth2 refresh-token clients (Google and anything RFC 6749), and `generic` for any other host.

## What it does not do

Read the [threat model](docs/04-threat-model.md) before trusting it with anything. In short: it stops *accidental* leaks (chats, git, logs, screenshots, SDK telemetry) and limits what a *dishonest* holder of a handle can do, but a process running as you with arbitrary code execution can still *use* an unlocked vault within policy, and a transparent proxy for tools like `gh` and `git` is not built yet. For a hostile agent you also want an OS sandbox.

## Documentation

[docs/00-README.md](docs/00-README.md) indexes the design: vision, decision records, product spec, threat model, architecture, cryptography, broker and policy, data model, API/CLI/MCP reference, implementation plan and as-built notes, testing and assurance, operations, UX, business.

## Roadmap

Next is **delegation**: grant a developer or agency the use of a key with a policy, an expiry, a signed log and a broker they do not control; revoke in one click. Then importers (1Password, Bitwarden, OS keychains), agent-framework plugins, a transparent proxy mode for CLIs, macOS Touch ID, and an attested hosted broker. Details and order in [docs/11](docs/11-implementation-plan.md).

## Building and contributing

```
cargo test --workspace            # core, daemon, CLI (158 tests)
cargo run -p usk -- --help
cd apps/desktop && npm install && npm run tauri dev
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md), privately please.

## License

Apache-2.0 (core, CLI, daemon, desktop). Cloud services, when added, will be AGPL-3.0.
