# 09 — API, CLI and MCP Reference

## Local management API (uskd, `http://127.0.0.1:7391/v1`)

Auth: `Authorization: Bearer <session token>` from `~/.unseenkey/daemon.token`. Also reachable over Unix socket `~/.unseenkey/uskd.sock` (Windows: `\\.\pipe\unseenkey`), where the token is optional because the OS enforces ownership.

All responses are JSON. Errors: `{ "error": "<code>", "message": "…" }`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/status` | `{locked, vault_id, version, uptime, cloud: {enabled, synced_at}}` |
| POST | `/v1/unlock` | body `{password}` or `{prf_output}`; returns `{ok}`; rate limited (5/min) |
| POST | `/v1/lock` | |
| GET | `/v1/secrets` | metadata list (no values) |
| POST | `/v1/secrets` | `{name, type, value \| fields, provider?, upstreams?, tags?}` |
| GET | `/v1/secrets/{id}` | metadata + policy summary + handles |
| PATCH | `/v1/secrets/{id}` | metadata or new value (creates a version) |
| DELETE | `/v1/secrets/{id}` | tombstone |
| POST | `/v1/secrets/{id}/reveal` | requires `{confirm:true}`; returns value once; audit `reveal`; optional `reason` |
| POST | `/v1/secrets/import` | multipart or `{format, content}` |
| GET/POST | `/v1/policies`, `/v1/policies/{id}` | CRUD; POST validates and returns `explanation` |
| POST | `/v1/handles` | `{secret_id, policy_id, label, callers?, expires_at?}` → returns the handle **once** |
| GET | `/v1/handles` | list (hashes, labels, counts, never handle strings) |
| DELETE | `/v1/handles/{id}` | revoke |
| POST | `/v1/handles/{id}/forget` | `{rule?}`: clear "allow always" decisions (one rule, or all). They live in the handle record, survive restarts, and are wiped by a policy change |
| GET/POST/DELETE | `/v1/unlock-methods`, `/v1/unlock-methods/{id}` | device unlock methods (Windows Hello); `POST /v1/unlock` also takes `{wrap_id, kek}` |
| GET | `/v1/callers` / POST / DELETE | manage MCP/device callers |
| GET | `/v1/audit?since=&kind=&limit=` | decrypted events for the owner |
| GET | `/v1/audit/verify` | re-hash the chain; returns first broken seq if any |
| GET | `/v1/approvals` / POST `/v1/approvals/{id}` | list pending; decide `{decision: allow\|deny, remember: bool}` |
| GET | `/v1/presets` | compiled presets |
| POST | `/v1/env-guard/scan` | `{path}` → detected secrets in `.env`-like files (values not returned, only positions) |
| POST | `/v1/env-guard/fix` | move detected secrets into the vault and rewrite the file with handles |

Server-sent events at `GET /v1/events` for the desktop app: `approval_requested`, `egress_blocked`, `use`, `lock`.

## Proxy routes

See [07](07-broker-and-policy.md). Example with the OpenAI SDK, no code changes:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:7391/p/openai/v1
export OPENAI_API_KEY=usk_h_4Qm7…
```

Anthropic:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:7391/p/anthropic
export ANTHROPIC_API_KEY=usk_h_…
```

Generic with template:

```bash
curl http://127.0.0.1:7391/p/generic/v2/things \
  -H "X-Usk-Upstream: https://api.example.com" \
  -H "X-Api-Token: {{usk:example}}"
```

## CLI (`usk`)

```
usk init                         create a vault (interactive: password, passkey?, recovery kit)
usk unlock | usk lock
usk status
usk doctor                       diagnose: daemon, port, token, env vars, MCP configs

usk add <name> [--type api_key] [--provider openai] [--upstream host]   (prompts for value, hidden)
usk add --from-env .env          import & optionally replace with handles
usk ls [--provider stripe] [--tag x]
usk show <name>                  metadata only
usk reveal <name> [--reason "…"] value, once, audited, requires confirmation
usk rm <name>
usk rotate <name>                (Phase 4) run provider adapter

usk handle create <name> [--policy chat] [--label "cursor"] [--caller mcp:cursor] [--expires 30d]
usk handle ls | usk handle show <label|id> | usk handle revoke <label|id>
usk add aws-dev            # AWS: paste the access key id, then the secret access key; or pipe a credentials section with --stdin
usk env aws-dev --policy s3-read-only   # AWS_ENDPOINT_URL + a handle as AWS_ACCESS_KEY_ID + a placeholder secret
usk add gdrive --type oauth2_client --upstream www.googleapis.com   # OAuth: client id, secret, refresh token, token URL; or pipe the token JSON with --stdin
usk env openai --camouflage             # a handle shaped like the provider's own key, for tools that check the format
usk handle forget <label|id> [--rule "POST /v1/refunds"]   # ask again for rules approved with "always"
usk policy ls | usk policy show <id> | usk policy edit <id> (opens $EDITOR, validates, explains)
usk policy explain <id>

usk env <name> [--policy chat] [--shell sh|powershell|cmd|dotenv]   print the variables for the provider preset (creates handle)
usk run --with VAR=name [...] -- <cmd…>   inject secrets into a child's environment (needs --allow-injection); output scrubbed; exit code propagates
usk secret set <name> [--allow-injection bool] [--no-scrub bool] [--notes …] [--tag …] [--upstream host]
usk guard scan [.env]            which lines look like secrets, and which can become handles
usk guard fix  [.env] [--dry-run] move them into the vault, rewrite the file with handles + base-URL variables
usk mcp --client <name>          stdio MCP bridge to the daemon's /mcp (what the clients' configs run)
usk mcp install <claude-code|claude-desktop|cursor|windsurf|all|custom-name>   register the client (usk_m_ token) and write its config
usk mcp clients | usk mcp remove <name>
usk approvals                    requests waiting for you (proxied calls parked on approval, MCP access requests)
usk approve [id|latest] [--remember] | usk deny [id|latest]
usk log [--since 1h] [--kind use] [--json]
usk log verify
usk export --out file.uskx | usk import file.uskx

usk cloud login | logout | sync | devices        (Phase 3)
usk grant create <name> --to user@x --policy stripe:payments --expires 30d   (Phase 3)
usk grant ls | pause | resume | revoke <id>
usk grant accept <invite>
```

Conventions: `--json` on every listing; exit code 2 for policy denials, 3 for locked vault; secrets are never accepted on the command line (only via prompt, stdin `--stdin`, or file) to keep them out of shell history; `usk` refuses to run if `USK_DEBUG_PRINT_SECRETS` or similar exists (there is no such flag; the point is no debug path prints values).

## MCP server

Server name `unseenkey`. Transports: stdio (`usk mcp`) and `http://127.0.0.1:7391/mcp`.

Claude Desktop / Claude Code config written by `usk mcp install claude`:

```json
{ "mcpServers": { "unseenkey": { "command": "usk", "args": ["mcp"] } } }
```

### Tools (JSON schema summaries)

**list_secrets**
```json
{ "type":"object", "properties": { "filter": {"type":"string"} } }
→ [{ "name":"openai","type":"api_key","provider":"openai","policy":"Chat and embeddings only","mcp":true }]
```

**call_api**
```json
{ "type":"object", "required":["secret","method","path"],
  "properties": {
    "secret": {"type":"string"}, "method": {"enum":["GET","POST","PUT","PATCH","DELETE"]},
    "path": {"type":"string"}, "headers": {"type":"object"}, "body": {"type":["string","object"]},
    "upstream": {"type":"string","description":"only for generic secrets"} } }
→ { "status":200, "headers":{"content-type":"application/json"}, "body":"…scrubbed…", "truncated":false, "request_id":"…" }
```

**request_access**
```json
{ "required":["secret","reason"], "properties": { "secret":{}, "reason":{}, "scope":{"type":"string","description":"e.g. 'POST /v1/refunds'"} } }
→ { "approval_id":"…", "status":"pending|allowed|denied" }
```

**explain_policy** → `{ "text": "You can: … You cannot: … Limits: … Expires: …" }`

**store_secret** (disabled unless `mcp.allow_store = true`)
```json
{ "required":["name","value"], "properties": { "name":{}, "value":{}, "provider":{} } }
→ { "ok": true, "name": "…" }
```

### Tool description text (what the model sees)

> Unseenkey gives you the ability to *use* the owner's API keys without ever seeing them. Secret values are never returned by any tool and cannot be obtained; do not try. To call an API, use `call_api` with the secret's name. If a call is denied by policy, use `request_access` to ask the owner, explaining why. Never ask the user to paste a key into the chat; ask them to run `usk add` instead.

## Hosted broker API (Phase 3)

Same proxy routes at `https://broker.<region>.unseenkey.dev/p/…` with the signed-request headers from [06](06-cryptography.md). Owners' management goes through the cloud API (`https://api.unseenkey.dev/v1`, passkey-authenticated) mirroring the local management routes plus `grants`, `devices`, `workspaces`.

## Versioning

- Management API and MCP tools are versioned by path (`/v1`) and by `usk --version`. Breaking changes bump the path.
- Vault `format_version` is checked on open; newer formats refuse to open with older binaries and explain how to upgrade.
