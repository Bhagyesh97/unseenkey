# 01 — Vision and Market

## Vision

**Secrets should be used, never seen.**

A developer should be able to build a Stripe integration without ever holding the Stripe key. An AI agent should be able to call the OpenAI API without the key ever entering its context window. A client should be able to hire an agency and know exactly how their keys were used, and cut access the day the contract ends.

Unseenkey makes the secret string disappear from everyday workflows and replaces it with a revocable, policy-bound, audited *right to use*.

## The problem

### Numbers (from public reports; verify before quoting externally)

- GitGuardian's *State of Secrets Sprawl* reported roughly **12.8M** new hard-coded secrets on public GitHub in 2023 and roughly **23.8M** in 2024, a year-on-year increase of about 25%.
- Around **70%** of secrets leaked in earlier years were **still valid** when re-tested. Rotation does not happen.
- Repositories where AI coding assistants were used showed a **higher leak rate** than the average. AI does not cause the problem, it accelerates it: it writes `.env` values straight into code and pastes them into logs and chats.
- Automated scanners pick up a fresh AWS or OpenAI key on public GitHub within **minutes**. Users routinely wake up to bills in the thousands.
- Private channels leak more than public ones: Slack, Jira, Confluence, Docker images and CI logs contain more live secrets than public repositories.

### Root causes

1. **Every tool asks for the raw string.** SDKs, `.env`, CI settings, agent configs, docker-compose. The plaintext must exist somewhere, so it can be copied anywhere.
2. **AI chats are a new, unmonitored leak channel.** The key enters a chat, a context window, a tool-call trace, provider logs and sometimes telemetry. Prompt injection can make an agent exfiltrate anything in its context.
3. **Client-to-developer handoff is broken.** Keys travel over WhatsApp, email and shared docs. The developer keeps them forever. Nobody rotates when the engagement ends.
4. **Rotation is painful**, so it never happens, so a single leak stays exploitable for years.
5. **Non-human identities outnumber humans** (services, bots, agents) and nobody has a clean way to give them scoped, expiring credentials.

## Who has the pain

| Segment | Concrete pain | Buying trigger | Willingness to pay |
|---|---|---|---|
| **Vibe coders / indie hackers** | Paste keys into Cursor/Claude/ChatGPT; commit `.env`; surprise bills | A leak, or a scare story on X/Reddit | Low per user, huge volume; free tier drives adoption |
| **Clients of freelancers/agencies** (founders, SMB owners) | Must hand Stripe/AWS/Google keys to strangers | Hiring a developer; a previous bad experience | Medium–high; fear of fraud is a strong motivator |
| **Freelancers and agencies** | Juggle many clients' keys; liability if one leaks | Onboarding a new client | Medium; it makes them look professional |
| **Teams shipping AI agents** | Agents need credentials, context windows are not safe | First production agent | High; fastest-growing budget line |
| **Enterprises** | Compliance, audit, NHI sprawl | Audit finding | Very high, slow sales, heavy requirements |

**Beachhead:** segments 1–3. Segment 4 is the growth engine. Segment 5 is a later phase.

## Competitive landscape

| Player | What it does | Why it does not solve this |
|---|---|---|
| HashiCorp Vault (IBM), CyberArk Conjur | Enterprise secrets engine | Heavy; nobody uses it for vibe coding or client handoff |
| AWS/GCP/Azure Secret Manager | Cloud-native storage | Single cloud, developer-only, not AI-aware, hands out plaintext |
| Doppler, Infisical, Bitwarden Secrets Manager | Sync secrets into env vars and CI | Still deliver the raw key to the app and the developer |
| 1Password (Developer tools, agent features) | Password manager expanding to developers/agents | General purpose; plaintext still reaches the consumer |
| Aembit, Astrix, Akeyless, Keycard | Workload / non-human identity | Enterprise-priced, enterprise-shaped |
| Arcade.dev, Composio, Nango | Auth and tool calling for agent builders | Built for builders, not for clients who own keys; OAuth-centric |
| GitGuardian, TruffleHog, gitleaks | Detect leaks | Reactive; nothing to do with storage or usage |
| Cloudflare AI Gateway, Portkey, LiteLLM | LLM proxies with key management | LLM-only; no client/developer delegation; not a vault |
| **Agent credential proxies (2026)**: Infisical Agent Vault (2.3k★, MITM proxy), OneCLI (YC, 3.5k★, MITM gateway + team agent platform, $149–499/mo), nono (4.3k★, kernel sandbox + phantom-token reverse proxy, by Sigstore's founder); small OSS: BlindKey, VeilKey, BlindVault, Veil, Trustless, agent-secrets | Agent uses the key, never sees it | All developer/DevSecOps-facing; **none** do client→developer delegation, attested brokers, owner-first UX, leak-harmless handles or first-class Windows. (internal survey, 2026-09-30; star counts as of that date) |

**What nobody packages for normal people:** *use without seeing* + *client-to-developer delegation with revoke* + *local-first, works offline*.

## Positioning

> **Unseenkey — the key your AI and your developer can use but never see.**

Three promises:
1. **Nothing to leak.** Handles instead of keys. A leaked handle is worthless.
2. **Delegate, don't share.** Give usage rights with a policy and an expiry. Revoke with one click.
3. **See everything.** Every use, by whom, to where, when, in a log nobody can alter.

## Impact if it works

- A category of leak (paste-into-chat) becomes technically impossible for users of the product.
- "Send me your Stripe key" becomes "send me a Unseenkey grant", the way "send me the file" became "send me the link".
- AI agents get a standard credential layer that is safe by default, which is a precondition for agents to be trusted with real business accounts.

## Risks (summary; full treatment in [04-threat-model](04-threat-model.md))

- **Honeypot.** A vault of everyone's keys is the most valuable target on the internet. Mitigated by local-first defaults, zero-knowledge storage, and enclaves for the hosted broker.
- **Trust bootstrap.** Unknown teams do not get Stripe keys. Mitigated by open source, audits, local mode.
- **Latency and availability.** A broker in the request path is a hop and a single point of failure. Mitigated by local brokers, edge deployment, per-customer fail-open/fail-closed.
- **The "power" problem.** A developer who can call any Stripe endpoint through the proxy can still do damage. The key is safe; the capability is not. Mitigated by endpoint-level policy, caps and approvals.
