# 15 — Business Model and Go-to-Market

## Positioning (one line)

**Unseenkey — hire a developer, run an agent, never hand over your keys.**

Supporting lines, in order (D-25): *Leaks become harmless* (handles, not keys) · *Made for the person who owns the keys* (plain-English policies, approvals on your phone, Windows too) · *Verify, don't trust* (open core, public threat model, attested broker). "Your AI can use the key but never see it" remains true and stays in the copy as a proof point; it is no longer the headline because ten other projects say it (internal survey, 2026-09-30).

## Pricing (Open-1: validate before launch)

| Tier | Price | Includes | For |
|---|---|---|---|
| **Free** | $0 | Local vault, local broker, MCP, unlimited secrets, 3 handles per secret, 1 device, community presets | Vibe coders; the growth engine |
| **Pro** | $8/user/month | Cloud sync, unlimited devices, passkey sync, approvals on phone, 90-day audit retention, priority presets | Individuals with multiple machines |
| **Delegate** | $19/owner/month + free for grantees | Grants, hosted broker (fair-use 500k calls/month, then $0.50 per 100k), owner dashboard, GitHub scanning auto-revoke | Clients and agencies (agency pays per client seat or client pays) |
| **Team** | $12/user/month | Workspaces, roles, shared secrets, SSO (Phase 4), 1-year audit retention | Small teams shipping agents |
| **Enterprise / Self-hosted** | From $15k/year | Helm, enclave broker, SCIM, audit export to SIEM, support SLA, source escrow | Companies |

Why grantees are free: adoption happens when Raj sends Dev a grant; a paywall on Dev kills the loop. The agency variant (agency pays, clients free) mirrors this for the other direction.

Unit economics: hosted broker cost per call is tiny (stateless Rust, ~µs of CPU + egress); KMS decrypt is cached per grant; the main cost is engineering and audits.

## Go-to-market

### Phase 1–2: developer-led, local, free
- Launch on GitHub with the threat model as the README's centrepiece; Hacker News "Show HN"; X/Twitter thread with the *paste-into-chat* demo (before/after).
- Content: "How your API key leaks through your AI agent (and the fix)"; "Handles: what if leaked keys were harmless?"; "The power problem: why encrypting your Stripe key isn't enough."
- Integrations day one: Claude Desktop/Code, Cursor, Codex, Windsurf MCP install; snippets for OpenAI/Anthropic/Stripe SDKs.
- Agent frameworks are the distribution channel (OneCLI became NanoClaw's default credential layer): ship OpenClaw, NanoClaw and Hermes plugins in Phase 2 and get listed in their docs; publish a nono credential-source profile.
- Windows-first content ("the only agent vault with a real Windows app") because the field is Mac/Linux.
- Community presets repo; recognition for contributors.

### Phase 3: the delegation loop
- Target freelancers and agencies on Upwork/Toptal/agency communities: "Stop asking clients for their keys" toolkit (email templates, a one-pager for clients).
- Target founders: "Hiring a dev? Never hand over your Stripe key" guides.
- Partnerships: agent platforms and AI IDEs (be the default credential layer); GitHub secret-scanning partner listing (credibility).

### Phase 4: teams and enterprise
- SOC 2 report, audit summary, enclave attestation documentation as sales assets.
- Design partners: 3 companies deploying agents in production.

## Differentiation vs. incumbents (for the pitch)

| Them | Us |
|---|---|
| Store the secret, hand it to whoever asks | Store the secret, never hand it out; broker uses it |
| Built for DevOps and CI | Built for people and agents |
| Enterprise pricing and setup | Free local mode, 5-minute setup |
| Trust us | Open source, local-first, attested enclaves |
| Sharing = copying | Delegation = revocable, policy-bound use with a signed log |

## Risks and how we answer them

| Risk | Answer |
|---|---|
| "1Password/Doppler will add this" | They hand out plaintext by design; changing that breaks their integrations. We start where they cannot. Speed and focus |
| "It's a honeypot" | Local-first by default; zero-knowledge sync; enclaves for delegation; published threat model; no operator recovery path |
| "Extra hop in production" | Local broker for self mode has no network hop; hosted broker is regional and stateless; fail-open available |
| "Nobody pays for security" | Clients pay to *not be defrauded*; agencies pay to look professional and avoid liability; teams pay for agent safety. Free tier for those who will not pay |
| Solo founder | Phase 1–2 alone is a complete, valuable product; open source builds a community before the cloud exists |

## Legal and trust assets

- Terms that state clearly what we can and cannot see in each mode.
- `SECURITY.md`, public threat model, published audit summaries, transparency page (uptime, incidents).
- Cyber-liability insurance before hosting delegated secrets.
- Trademark search for "Unseenkey" before public launch (availability of registries and domains was checked 2026-09-30; see D-01).

## Metrics dashboard (internal)

- Activation: install → first proxied call (target < 5 min median, > 50% of installs).
- Retention: weekly active vaults; handles created per user.
- Loop: grants sent → accepted → active after 30 days.
- Safety: egress blocks, leaked-handle reports, zero plaintext incidents.
- Revenue: Pro/Delegate conversion, agency seats.

## Twelve-month picture (if it goes well)

- 10k installs, 2k weekly-active vaults, 500 paying, 1k grants active, listed as a GitHub secret-scanning partner, one external audit published, two agent-platform partnerships. That is a fundable seed story or a sustainable indie business, whichever you prefer.
