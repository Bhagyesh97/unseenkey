# 10 — Tech Stack and Repository Layout

## Choices

| Layer | Choice | Why |
|---|---|---|
| Core language | **Rust** (stable, edition 2024) | Memory safety for code holding plaintext; one binary; WASM target; strong crypto ecosystem |
| Async runtime | tokio | Standard |
| HTTP server | axum + hyper | Mature, tower middleware, HTTP/2 |
| HTTP client | reqwest (rustls) | Streaming, HTTP/2, no OpenSSL |
| TLS | rustls + `rustls-native-certs` / `webpki-roots` | Memory-safe TLS |
| Crypto | RustCrypto (`argon2`, `chacha20poly1305`, `hkdf`, `blake3`, `ed25519-dalek`, `hpke`), `zeroize`, `subtle` | Audited, pure Rust, WASM-compatible |
| Storage | SQLite via `rusqlite` (bundled, SQLCipher not needed: we encrypt records ourselves) | Single file, robust, portable |
| Pattern matching | `aho-corasick` | Scrubber and egress guard |
| Serialization | `serde`, `serde_json`, `serde_yaml` (policies), `toml` (config/presets) | |
| CLI | `clap` v4, `dialoguer` for prompts, `rpassword` | |
| Desktop | **Tauri 2** | Rust backend = same crate; tiny; system webview |
| UI | React 19 + TypeScript + Vite + Tailwind + Radix primitives | Fast to build, accessible primitives |
| WASM | `wasm-bindgen`, `wasm-pack`, IndexedDB via `idb` | Same core in browser |
| MCP | `rmcp` (official Rust SDK) or a minimal in-house implementation if the SDK lags | Spec compliance |
| Cloud services | Rust (axum), Postgres (`sqlx`), Redis/NATS, S3-compatible object store | Same language, one team |
| Enclaves (Phase 4) | AWS Nitro Enclaves, `aws-nitro-enclaves-nsm-api` | Attestation with PCR measurements |
| Passkeys | `webauthn-rs` (server), Tauri plugin using platform APIs (client), browser WebAuthn (web) | PRF extension support |
| Packaging | cargo-dist for CLI/daemon; Tauri bundler for desktop; Homebrew tap, winget, scoop, `.deb`/`.rpm`, AUR | |
| Signing | Sigstore cosign for artifacts; Apple notarization; Windows Authenticode (EV cert) | Update trust |
| CI | GitHub Actions; matrix macOS/Windows/Linux + wasm32 | |
| Supply chain | `cargo deny`, `cargo audit`, `cargo vet` (later), Dependabot, SBOM via `cargo cyclonedx`, reproducible builds with pinned toolchain | |

Alternative considered: TypeScript/Node for everything (faster for a solo dev familiar with it). Rejected for the core (see D-15) but TypeScript is used for the UI and for optional thin SDK helpers.

## Repository layout (monorepo)

```
unseenkey/
├── Cargo.toml                 # workspace
├── crates/
│   ├── core/                  # unseenkey-core: crypto, vault, policy, broker, audit, handles, mcp, sync, grants
│   │   ├── src/
│   │   │   ├── crypto/        # kdf.rs aead.rs hpke.rs keys.rs secret_bytes.rs
│   │   │   ├── vault/         # store.rs records.rs import.rs export.rs search.rs
│   │   │   ├── storage/       # sqlite.rs indexeddb.rs memory.rs trait.rs
│   │   │   ├── policy/        # schema.rs eval.rs explain.rs presets/ (toml files included via include_str!)
│   │   │   ├── broker/        # pipeline.rs ingress.rs resolve.rs inject.rs hostlock.rs egress.rs scrub.rs forward.rs adapters/{bearer,header,basic,query,sigv4,oauth2,template}.rs
│   │   │   ├── audit/         # log.rs chain.rs sign.rs
│   │   │   ├── handles/
│   │   │   ├── mcp/           # tools.rs server.rs
│   │   │   ├── sync/
│   │   │   └── grants/
│   │   └── tests/             # vectors/, integration tests
│   ├── uskd/                   # daemon binary: axum server, lifecycle, platform (mlock, keychain, peer check)
│   ├── usk/                    # CLI binary
│   ├── wasm/                  # wasm-bindgen wrapper for web
│   ├── cloud-accounts/        # Phase 3
│   ├── cloud-sync/
│   ├── cloud-broker/
│   ├── cloud-events/
│   └── cloud-scan/
├── apps/
│   ├── desktop/               # Tauri 2 app (src-tauri/ + React UI in src/)
│   └── web/                   # Phase 3 web app (React, uses crates/wasm)
├── presets/                   # provider TOML presets (source of truth; embedded at build)
├── sdk/                       # optional thin helpers: js/, python/ (set base_url + handle; nothing else)
├── deploy/                    # docker-compose.yml, helm/, fly.toml, terraform/ (Phase 3+)
├── docs/                      # these documents + ADRs
├── scripts/                   # release, sbom, vectors generation
├── SECURITY.md  LICENSE-APACHE  LICENSE-AGPL (cloud crates)  CONTRIBUTING.md
└── .github/workflows/         # ci.yml release.yml audit.yml
```

## Crate boundaries and rules

- `core` has **no** network listeners and no CLI; it exposes types and async functions. This keeps it testable and WASM-buildable (`--no-default-features --features wasm`).
- `uskd` is the only crate that binds sockets. `usk` talks to `uskd`, except `usk mcp` and `usk run`, which link `core` directly.
- Cloud crates depend on `core` for policy evaluation and envelope handling so the hosted broker runs the identical pipeline.
- `#![forbid(unsafe_code)]` everywhere except a tiny `platform` module (mlock, keychain FFI, Windows handle-inheritance flags) that is reviewed separately. Today: `crates/usk/src/platform.rs` (two Win32 calls, `#![deny(unsafe_code)]` at crate level with a module-scoped allow).
- `SecretBytes` never implements `Serialize` for JSON; the only way to serialize is inside `vault::records` encryption. Clippy lint (custom `dylint`, later) or code review enforces it.
- Logging via `tracing` with a global layer that redacts any string matching the scrubber automaton, as defence in depth (INV-1). Log level `debug` never logs bodies or headers.

## Build and dev

```
rustup toolchain: pinned in rust-toolchain.toml
cargo build -p usk -p uskd                 # CLI + daemon
cargo test --workspace                   # unit + integration
cargo test -p unseenkey-core --target wasm32-unknown-unknown   # via wasm-pack test --headless --chrome
cd apps/desktop && pnpm i && pnpm tauri dev
cargo deny check && cargo audit          # every CI run
```

Dev fixtures: a `mock-upstream` binary in `crates/uskd/tests/` that echoes headers (so tests can assert injection without touching real APIs) and streams SSE.

## Coding standards

- `cargo fmt`, `cargo clippy -D warnings`.
- Every public function in `crypto` has a doc comment citing the construction and a test vector.
- Errors via `thiserror` in `core`, mapped to the error codes in [07](07-broker-and-policy.md) at the edge; error `Display` must not include secret material (tested by a grep-style unit test over rendered errors).
- No `unwrap` in non-test code in `core`/`uskd`.

## Versioning and release

- SemVer; `usk` and `uskd` versions must match (uskd refuses a mismatched client).
- Release = tag → CI builds all targets → cosign signs → SBOM attached → Homebrew/winget/scoop PRs automated → desktop auto-updater checks a signed manifest (Tauri updater with our public key embedded).
