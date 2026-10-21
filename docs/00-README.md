# Unseenkey — Project Documentation

> **Unseenkey**: a vault where humans, AI agents and developers can *use* API keys, credentials and passwords without ever *seeing* them.

Name chosen 2026-09-30 after availability checks (see D-01 in [02](02-brainstorm-and-decisions.md)). Conventions: CLI `usk`, daemon `uskd`, token prefixes `usk_h_` / `usk_s_` / `usk_m_` / `usk_i_`, template `{{usk:name}}`, headers `X-Usk-*`, data dir `~/.unseenkey/`, crate `unseenkey-core`.

## How to read these docs

| # | Document | Read it when |
|---|---|---|
| 01 | [Vision and market](01-vision-and-market.md) | You want the *why*: the problem, the users, the positioning |
| 02 | [Brainstorm and decisions](02-brainstorm-and-decisions.md) | You want to know *why* the design is the way it is (ADR style) |
| 03 | [Product spec](03-product-spec.md) | You need features, user stories, MVP scope and phases |
| 04 | [Threat model](04-threat-model.md) | Before touching any security-sensitive code |
| 05 | [Architecture](05-architecture.md) | You need the components, data flows and deployment modes |
| 06 | [Cryptography](06-cryptography.md) | You are implementing or reviewing the crypto |
| 07 | [Broker and policy](07-broker-and-policy.md) | You are building the proxy, injection, policy engine or MCP server |
| 08 | [Data model](08-data-model.md) | You need entities, schemas and file formats |
| 09 | [API, CLI and MCP reference](09-api-cli-mcp.md) | You are building or integrating with the interfaces |
| 10 | [Tech stack and repo layout](10-tech-stack.md) | You are setting up the codebase |
| 11 | [Implementation plan](11-implementation-plan.md) | You are planning the work |
| 12 | [Testing and security assurance](12-testing-and-assurance.md) | You are writing tests or preparing for an audit |
| 13 | [Operations](13-operations.md) | You are deploying, running or responding to incidents |
| 14 | [UX flows](14-ux-flows.md) | You are designing screens or the CLI experience |
| 15 | [Business model and go-to-market](15-business-and-gtm.md) | You are thinking about pricing, launch and growth |

## One-paragraph summary

Today every SDK, `.env` file, CI system and AI agent demands the raw secret string. Once the string exists in plaintext it gets pasted into chats, committed to git, printed in logs and stolen by bots within minutes. Unseenkey replaces the string with a **handle**. The handle is useless on its own: a local or hosted **broker** resolves it to the real secret at the last possible moment, injects it into the outgoing request, enforces a **policy** (which host, which endpoints, how often, until when, with whose approval), scrubs secrets from the response, and records everything in a tamper-evident **audit log**. Secrets are encrypted client-side, so the cloud (when used at all) stores only ciphertext. A **client** can grant a **developer** or an **AI agent** the right to use a key and revoke it with one click; the developer never sees it.

## Two trust modes (the most important concept)

| | Self mode | Delegation mode |
|---|---|---|
| Whose keys | Mine | The client's |
| Who uses them | Me, my agents, my scripts | A developer, an agency, an agent I don't control |
| Threat | *Accidental* leak (chat, git, logs) | *Intentional* misuse or theft by the user |
| Where the broker runs | My machine (loopback) | Somewhere the user **cannot** control: hosted broker, client-owned server, or attested enclave |
| Phase | 1–2 | 3–4 |

Every design question in these docs is answered separately for the two modes. Confusing them is the easiest way to build something that *feels* secure but is not.

## Status

- Date: 2026-10-22 (design 2026-09-30; repository public and domain `unseenkey.com` registered 2026-10-21/22)
- Stage: alpha. Phase 0, Phase 1, M2.1 (MCP), M2.2 (desktop) and M2.3 slice 1 (AWS SigV4, camouflage handles, OAuth2 refresh) are built and tested; see the *As built* notes in [11](11-implementation-plan.md). Delegation (Phase 3) is not built.
- Author: Bhagyesh (product owner); design assisted by Claude
- The competitive research that informed D-23 to D-27 is kept outside the repository; the decisions record what it concluded.
