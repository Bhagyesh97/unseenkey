# Changelog

The top section of this file becomes the release notes when a `v*` tag is pushed.

## 0.1.7 — 2026-10-31

- **Claude Code plugin.** `claude plugin marketplace add Bhagyesh97/unseenkey`, then `claude plugin install unseenkey@unseenkey`: Claude Code gets the Unseenkey tools and a skill that tells it to use them for any API key and never to ask you to paste one. Needs `usk` on your PATH and a vault (`usk init`). Use the plugin or `usk mcp install claude-code`, not both.
- **An AI tool connects itself.** `usk mcp --client <name>` with no token registers the tool on first use and keeps its token, so an MCP config or plugin needs no `usk mcp install` first. It only ever registers a new name: one that is already registered, or that you disconnected, is left alone, and the tool says to run `usk mcp install <name>` (which asks for your password). While the vault is locked or not set up, the tool stays connected and says what to do instead of failing to start.
- **A disconnected AI tool stays disconnected.** After `usk mcp remove <name>`, nothing can register that name again without your password (409 `caller_removed`); `usk mcp install <name>` reconnects it.
- **AI tools connected from the desktop app work.** The configs the app writes run the app itself as `mcp --client <name>`, which opened the app instead of answering; the app now runs the bridge when started that way.

## 0.1.6 — 2026-10-31

A security fix; no new features.

- **An AI tool's identity can no longer be taken over with the session token.** Registering an MCP client under a name that already existed silently replaced its token, and the new token kept everything approved for that name; any program that could read `daemon.token` could become "claude-code" that way. An existing name now answers 409 `caller_exists`; replacing it needs the owner (`usk mcp install` asks for the password, the app uses the confirmation it already holds). Registering needs an unlocked vault, and registrations, replacements and removals are audited (`caller_registered`, `caller_replaced`, `caller_removed`). The app says "New AI tool connected" when one appears, and the activity page shows all three in plain words.

## 0.1.5 — 2026-10-30

Security fixes from a full review of the code; no new features.

- **The session token is no longer enough to reveal, approve or widen access.** `daemon.token` is readable by every program running as you, an AI tool with a shell included, and it used to open every management route. Revealing a value, `usk run` injection, approving or denying a request, enrolling a device unlock, changing the care level or idle lock, naming a policy for a new handle, replacing a policy and resuming a handle now need an **owner token** as well: `POST /v1/unlock` returns one, `POST /v1/confirm` (password or Windows Hello) issues one on an unlocked vault, it travels in `X-Usk-Owner`, lives only in memory and dies with every lock. The CLI asks for the password once per such command ("Vault password (to confirm it is you)"); the app confirms through Windows Hello when it is set up and otherwise asks for the password in a dialog. Adding keys, listing, and care-level handles (`usk guard fix`, AI tools' first use) still need only the session token. Error: 403 `owner_required`.
- **`usk approve` with several requests waiting asks for the id.** `latest` could approve a request a tool slipped in just before you answered; it now refuses (409 `ambiguous`) unless exactly one request is pending.
- **Compressed replies are unpacked before scrubbing.** The caller's `Accept-Encoding` was forwarded and the provider's compressed reply passed through unread, so a key echoed inside it reached the caller. The broker now strips that header, negotiates gzip, brotli and deflate itself and unpacks before scrubbing; a reply in an encoding it cannot unpack is refused (502 `undecodable_response`) and audited.
- **A deleted audit head is tampering, not an old log.** The vault header records that the log has had a keyed head; from then on a missing one is reported as `audit_tampered` (state `removed`) instead of being tolerated as a pre-0.1.1 log. Logs that truly predate heads are still accepted.
- **Replaced and deleted values are erased.** Superseded versions of a secret's value, its metadata, a handle (its policy, its pre-revocation state) and a project are deleted on every write (`secure_delete` is on), and deleting a secret purges every version of the value. Old keys can no longer be decrypted out of the file with the password, and removing the newest row cannot revive a revoked handle or an older, wider policy.
- **A handle never reaches the provider.** When an SDK put the handle in a header the preset does not use (`x-api-key` on a bearer provider) or in `?key=`, it travelled on to the provider; the broker now empties the place it found the handle in.
- **The CLI and app refuse a `daemon.addr` that is not loopback.** A tampered file naming another machine would have received the session token, the password and the values a command sends.
- **A value that starts with `hex:` is stored as typed.** It was decoded as hex on the way back.
- **Desktop updater: zip 9.1.3.** `tauri-plugin-updater` 2.14.1 drops zip 4.6.1 (RUSTSEC-2026-0367/0368/0369). CI now audits the desktop lockfile too.
- **Release and CI workflows pin every action to a commit.** A moved tag can no longer change what runs in the job that holds the signing keys.
- Threat model and API reference updated to say exactly what the session token, the owner token and a handle each allow.

## 0.1.4 — 2026-10-30

- **How careful: relaxed, balanced (new default) or strict.** On your own machine the risk is not you but what touches your keys: an AI tool talked into misusing them, a package you never read, a loop that runs up a bill. The access Unseenkey hands out by itself (an AI tool's first use of a key, a handle created without a policy) now follows one setting in Settings or `usk care`:
  - *Relaxed*: anything goes; deleting things and moving money out (refunds, payouts, transfers) ask you first.
  - *Balanced*: anything goes except deletes, money out, and key, billing or account changes, which ask you first with "Always allow this". Taking a payment or calling a model just works.
  - *Strict*: each provider's cautious default, as before (Stripe read only); best for keys you share.

  Allowed websites, response scrubbing and the activity log apply at every level. Changing the level updates the access Unseenkey handed out (and AI-tool access from before that still has its untouched default), never access you set up or edited yourself. The level is kept in `config.toml` (`care`), set with `PATCH /v1/settings {care}`, shown in `/v1/status`, and audited. Presets may name what asks first (`ask_first`); otherwise it is deletes plus the deny rules of their non-full policies.

- **The vault locks itself again while the app is open.** The app checks status and approvals every few seconds and keeps the event stream open, and every one of those requests counted as "the owner is here", so the idle lock never fired as long as the app ran. Those background reads no longer reset the timer; anything you actually do still does.
- **Choose when it locks.** Settings has "Lock when not used for" (5, 15, 30 minutes, 1 or 4 hours, never); it takes effect at once and is kept in `config.toml` (`PATCH /v1/settings {idle_lock_minutes}`, audited as `settings_changed`). Locking Windows or sleep still lock it either way.
- **Activity in plain words.** Each entry is a sentence ("Claude Code used openai: sent api.openai.com/v1/chat/completions · OK", "“contractor” was stopped from using stripe-live: the rules for this access do not allow it"), grouped by day, with today's counts on top, simple filters (keys used, blocked, alerts, requests to you, changes, lock and unlock) and search. Click an entry for the technical record and the matching `usk log` command. "Verify log" became "Check nothing was changed" with a plain answer.
- **Approvals, Agent access and Settings in plain words.** "Claude Code wants to use your Stripe key to send a request to …", "Allow this once / Always allow this / Don't allow"; access entries named after the tool, "working / removed / expired", what each may do folded under one line; technical details (labels, ids, raw rules, the vault file, the service version) one click away.

Paste and done:

- **65 providers instead of 18.** New presets for AI (xAI, Together, Fireworks, Deepgram, ElevenLabs, AssemblyAI, Cohere, DeepSeek, Replicate, Perplexity, Cerebras), payments (Paddle, Polar, Paystack, Mollie, Mercado Pago, Lemon Squeezy, Square), hosting and databases (DigitalOcean, Linode, Vultr, Hetzner, Netlify, Render, Heroku, Neon, Supabase management), email and messaging (Postmark, Brevo, Loops, beehiiv, Vapi, Telnyx, Discord bots), and everyday tools (Figma, Airtable, ClickUp, Coda, Calendly, Tally, HubSpot, Clerk, CircleCI, Mapbox, YouTube, OpenWeatherMap, Alpha Vantage). Each has a safe default ("everything except deletes and account, key and billing changes"), read-only and full. They come from [the provider research](docs/research/provider-catalogue.md).
- **Paste a key, the rest fills in.** A key's shape decides first, then a prefix only one provider uses (Cloudflare's new `cfut_`/`cfat_`, Brevo `xkeysib-`, Paddle, Neon, Heroku …), then the name you gave it (`cloudflare`, `OPENAI_API_KEY`). Allowed websites come from the provider. In the app, an unrecognised key opens a searchable list of providers; "It is not in the list" asks only for the website. `POST /v1/detect` does this without storing or sending anything.
- **Every key can be tested.** `usk add` and the app send one read-only request to the key's own provider right after saving ("It works." or "This key was refused", with what to do); `usk secret test <name>`, "Test key" in the app and `POST /v1/secrets/{ref}/test` do it on demand. The key goes only to its provider, on a host it is locked to, and each test is audited (`key_tested`). Test suites set `USK_NO_KEY_TEST=1`.
- **Providers that do not say `Bearer`.** A new auth style sends `Authorization: <scheme> <key>` (Deepgram `Token`, Discord `Bot`), in both directions through the broker.
- `usk presets --json` lists each provider's category, whether it can be tested, and its rules; the website's provider list is generated from it.

## 0.1.3 — 2026-10-30

From a second Claude Code session stuck asking its owner to "check" a Hostinger and a Cloudflare key:

- **`usk secret replace <name>` and "Replace value" in the app.** There was no way to put a new key under an existing name: `usk secret set` only changes settings, so following the advice to "store it again" changed nothing. The handles keep working with the new value.
- **Pasted keys lose stray spaces and line breaks.** The app sent a pasted key exactly as typed, and the daemon stored it that way; providers answer such a key with a bare 401. Single-line values are now trimmed by the app, the CLI and the daemon; multi-line ones (PEM keys) are kept as given.
- **A refused key says what to do.** When the provider itself answers 401 or 403, `call_api` adds a `hint`: retrying will not help, here is how the owner replaces the key; for a secret without a provider, that no credentials were sent and how to set one.
- **The app notices an outdated service.** If the running daemon is another version than the app (an older install, or a developer build an MCP client started first), a banner says so and offers "Restart the service".

- **The first unlock after the daemon starts no longer fails with "missing or invalid session token".** A new daemon opens its port a moment before it writes its token, and the app and CLI checked only that the port answered, so the first request could carry the previous daemon's token; the second try worked. They now check with the token and wait until it is the current one.

## 0.1.2 — 2026-10-24

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
