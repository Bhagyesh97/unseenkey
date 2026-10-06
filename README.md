# Unseenkey

**Use API keys, credentials and passwords without ever seeing them.**
Delegate their use to developers, agencies and AI agents with a policy, an expiry and a signed audit log. Revoke with one click.

> Status: early development (Phase 0). Nothing here is ready to protect real secrets yet.
> Design documentation lives in [`docs/`](docs/00-README.md); start with the
> [threat model](docs/04-threat-model.md), which also lists what Unseenkey does **not** protect against.

## Why

Every SDK, `.env` file and AI agent asks for the raw secret string, and once it exists in plaintext it gets pasted into chats, committed to git and stolen within minutes. Unseenkey replaces the string with a **handle**. A local or hosted **broker** resolves the handle at the last moment, injects the real secret into the outgoing request, enforces a **policy** (host, endpoints, rate, expiry, approval), scrubs secrets from the response and records the use in a tamper-evident **audit log**. Secrets are encrypted client-side; the cloud, when used, stores only ciphertext.

## Layout

```
crates/core   unseenkey-core: crypto, vault, policy, broker, audit (no sockets, no CLI)
crates/daemon unseenkey-daemon: loopback management API, broker route, MCP server
crates/usk    usk (CLI) and uskd (daemon) binaries
apps/desktop  desktop app (Tauri 2 + React), built separately; see its README
docs/         design documents and decision records
```

## Building

Requires stable Rust (see `rust-toolchain.toml`).

```
cargo test --workspace
cargo run -p usk -- --help
```

## Try it (local, nothing leaves your machine)

```
usk init                                   # password + 24-word recovery phrase
usk add anthropic                          # paste a key or a Claude Code token (hidden prompt)
usk env anthropic --policy chat            # prints ANTHROPIC_BASE_URL + a usk_h_… handle
claude -p "hello"                          # Claude Code now goes through the broker
usk add aws-dev && usk env aws-dev         # AWS too: boto3, the AWS CLI and the JS SDK sign with a placeholder, the broker signs for real
usk log                                    # every call, hash-chained
usk guard fix .env                         # replace real keys in a .env with handles
usk run --with DATABASE_URL=prod-db -- app # for things that cannot be proxied (audited, scrubbed)
```

## Security

See [SECURITY.md](SECURITY.md). Please report privately.

## License

Apache-2.0 (core, CLI, daemon, desktop). Cloud services, when added, are AGPL-3.0.
