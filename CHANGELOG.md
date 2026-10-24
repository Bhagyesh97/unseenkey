# Changelog

The top section of this file becomes the release notes when a `v*` tag is pushed.

## Unreleased

Projects:

- **Keep each app's keys together.** A project is a code folder (or several) and the keys it uses; one key can belong to several projects. The app opens on a new Projects page; the CLI has `usk project add | ls | show | attach | detach | set | rm`.
- **Protect a project in one step.** "Protect a project" in the app (or `usk project protect` in a folder) picks the folder, finds the real keys in its `.env` files, moves them into the vault, leaves handles behind and files everything under the project. `usk guard fix --project` and `usk handle create --project` do the parts by hand.
- **AI tools see only the project they work in.** The MCP bridge tells the daemon which folder its client runs in (`USK_PROJECT_DIR`, then `CLAUDE_PROJECT_DIR`, then its working folder). Inside a project's folder, `list_secrets`, `call_api`, `explain_policy` and `request_access` see only that project's keys and say so plainly when asked for another; outside every project nothing changes. This narrows what an honest agent sees; it is not a wall against a hostile program on your machine.
- **A daily limit per project.** `cap_per_day` counts requests across every handle made for the project and answers `429 project_cap_reached` at the limit, so one runaway script cannot run up a bill on all of an app's keys.
- **A status panel.** The Projects page shows whether the vault is unlocked, which AI tools have connected and when, and whether an update is waiting, each with its fix one click away.
- **Plainer words in the app.** Secrets are "Keys", handles are "Agent access", hosts are "Allowed websites". Each key shows the projects that use it. The two-pane pages stack on narrow windows instead of cutting off.

- **Revealing a value in the app shows it.** The daemon announces every reveal, and the app remounted the Secrets page on any daemon event, so the value (and the open secret) vanished the moment it arrived. Pages now reload in place on events; a revealed value, a selection or a half-filled form survives. The same remount could wipe the Handles create form and the Activity filter.

Found by an agent using the broker from a second Claude Code session:

- **Deleting a secret revokes its handles.** `usk rm` (and the app's delete) left the secret's handles active; `usk handle ls` showed them against "(deleted)". Delete now revokes every active handle of the secret first, each with its own `handle_revoked` audit event (`reason: secret_deleted`), and the CLI says how many went.
- **One daemon per vault.** Nothing stopped a second `daemon run` on the same vault when the listen address allowed it; each daemon holds its own copy of the index, so changes made through one were invisible to the other. A daemon now refuses to start while the vault's runtime files point at a live daemon, naming its address and pid.
- **MCP `call_api` no longer reads a missing secret as "no provider preset".** The handle lookup now carries the secret's metadata with it, and an unknown name answers with "no secret named …; call list_secrets, or ask the owner to run `usk add <name>`".

## 0.1.1 — 2026-10-23

Integrity and limits:

- **The audit log now notices when it has been cut short.** The hash chain is unkeyed, so anyone who could write the vault file could delete the newest events (or rewrite the log from some point on) and `usk log verify` would still pass. Every append now also records a *keyed head*, the newest event's position and hash under a key derived from the vault key, in the same transaction. An unlocked `usk log verify` (and the app's Verify log) checks the chain **and** the head and says which it checked; a locked verify says the head could not be checked. Existing vaults get a head with their next event. The README's audit wording now matches what the code does: the event is committed before the response reaches the caller.
- **Caps hold across a restart.** Per-minute and per-day counters lived only in memory, and the lifetime counter was persisted every 100 uses, so a daemon restart or crash handed a capped handle a fresh allowance. On unlock the daemon now rebuilds the sliding windows from the last day of `use` events, and the vault adds back any uses the log holds past the point a handle's record was last written. Nothing changes on disk per request.
- **Using a handle counts as activity for the idle lock.** Only management calls did before, so an agent calling through the broker for fifteen minutes straight found the vault locked under it.

Desktop app:

- **A real look.** One visual system with unseenkey.com: icons in the sidebar, provider avatars, chips coloured by meaning, approval cards with a countdown, sectioned settings, empty states that say what to do next, a light theme when the OS asks for one.
- **Edit a secret's settings in the app:** name, provider, allowed hosts, tags and notes (what `usk secret set` does); provider and hosts can also be given when adding a secret.
- User presets (`<vault dir>/presets/<id>.toml`) show up in the app's provider lists.
- The Handles page no longer goes blank against a daemon older than the app.

Fixes from the first real use of a provider without a preset (calling Hostinger's API through the generic route):

- **Template mode kept no `Authorization` header.** `Authorization: Bearer {{usk:name}}` on the generic route was stripped before the placeholder was filled in, so a generic secret could never call a plain bearer API. Headers that carry a `{{usk:…}}` placeholder now survive the strip.
- **A value that does not fit in a header is an error, not a silent drop.** A stored value ending in a newline made the substituted header vanish, which looked like a bad token; the broker now answers `malformed_request` naming the header. `usk add` trims trailing spaces off single-line values.
- **`--upstream` accepts what people type.** `https://api.example.com/v1/` and `API.EXAMPLE.COM` are normalised to `api.example.com` on `usk add` and `usk secret set`; wildcards are kept.
- **`usk secret set --provider`** changes a secret's provider (and brings the preset's hosts unless `--upstream` is given) instead of `rm` and re-paste.
- **User presets without a rebuild:** drop `<id>.toml` into `<vault dir>/presets/` and the daemon and CLI load it beside the built-in ones (a built-in id is overridden). `usk presets` marks them "(yours)".
- **MCP `request_access` can ask for a host:** pass `upstream` and an approval also adds the host to the secret's allowed hosts, so "approved, retry" is no longer followed by `host_not_allowed`.
- **Clearer refusals:** `host_not_allowed` says the `usk secret set … --upstream` line that fixes it; the generic route's `unknown_handle` says to send `X-Usk-Handle` and put `{{usk:<secret>}}` where the secret goes.
- **New preset:** Hostinger (`read-only`, `deploy`, `full`).

## 0.1.0 — 2026-10-22

First public release. Alpha: the local parts work and are tested on Windows, macOS and Linux, but no external security audit has happened yet. Use it with keys you can rotate, and read the [threat model](docs/04-threat-model.md) before trusting it with anything.

### What you get

- **`usk` CLI and `uskd` daemon.** A password-protected vault (Argon2id, XChaCha20-Poly1305, 24-word recovery phrase, keys locked in memory) and a loopback broker that swaps handles for real keys at the last moment, enforces a per-handle policy, scrubs the key out of responses and writes every call to a hash-chained audit log.
- **18 provider presets** with ready-made policies and plain-English explanations: Anthropic, OpenAI, Google AI, Groq, Mistral, OpenRouter, GitHub, Stripe, Slack, Notion, Cloudflare, Vercel, Supabase, Twilio, SendGrid, Resend, AWS, and `generic` for any other host.
- **AWS SigV4:** boto3, the AWS CLI and the JS SDK sign with a placeholder; the broker re-signs with the real key. **OAuth2 refresh-token clients** (Google and any RFC 6749 token endpoint): the broker keeps the access token fresh.
- **Camouflage handles** that pass an SDK's own key-format checks (`sk-proj-usk-…`, `sk_live_usk…`); every format carries the `usk` marker.
- **Caps, canaries and incident responses:** `--cap 1000/day` hard stops, `--canary` tripwire handles that never work and lock the vault when used, and a per-handle response to a burst of refused requests (alert, throttle, approve, pause or lock).
- **MCP server** for Claude Code, Claude Desktop, Cursor and Windsurf (`usk mcp install <client>`): the agent gets tools, never values. Live approvals with "allow once / always / deny".
- **`.env` guard:** `usk guard fix .env` moves the real keys into the vault and rewrites the file with handles.
- **Desktop app** (Windows, macOS, Linux): unlock, secrets, handles, approvals, activity with chain verification, one-click MCP setup, Windows Hello unlock, lock on sleep and screen lock, signed auto-updates.
- **Fail closed everywhere:** host lock per secret, browser-origin requests refused, unmatched requests refused.

### Not in this release

- Delegation to other people through a hosted broker (designed, not built).
- Importers (1Password, Bitwarden, OS keychains), agent-framework plugins, a transparent proxy for CLIs such as `gh` and `git`.
- macOS Touch ID and Linux session-lock hooks (password unlock works everywhere).
- Spend metering in currency, baseline anomaly detection, caller binding.

### Installing

Pick the archive for your platform below; each has a Sigstore signature (`.sig` + `.pem`) and is listed in `SHA256SUMS`. Desktop installers carry minisign signatures for the updater. The installers are not yet code-signed, so Windows SmartScreen and macOS Gatekeeper will warn on first launch.

From source: `cargo install --locked --git https://github.com/Bhagyesh97/unseenkey usk` (Rust 1.85 or newer).
