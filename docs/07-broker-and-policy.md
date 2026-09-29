# 07 — Broker, Policy Engine and MCP Server

The broker is the heart of the product. It is the only component that turns a handle into a real credential, and it does so for one outgoing request at a time.

## Routes

| Route | Purpose | Auth |
|---|---|---|
| `/p/<preset>/<path…>` | Base-URL proxy for a known provider (e.g. `/p/openai/v1/chat/completions`) | Handle in the provider's usual header |
| `/p/generic/<path…>` | Proxy to any upstream named in `X-Usk-Upstream`, with template substitution | Handle in `X-Usk-Handle` or templates in request |
| `/v1/*` | Management API (vault, handles, policies, audit) | Session token |
| `/mcp` | MCP streamable HTTP | Session token or per-client MCP token |
| `/healthz` | Liveness | none (no info beyond `ok`) |

## Request pipeline (local and hosted share this code)

1. **Ingress checks**
   - Local: reject if `Origin`, `Referer`, or any `Sec-Fetch-*` header present → 403 `browser_origin_rejected`. Reject if `Host` is not `127.0.0.1:7391`/`localhost:7391`/`[::1]:7391`.
   - Hosted: verify TLS, device signature, timestamp, nonce.
   - Body size limit (default 32 MiB, streaming for larger where allowed).
2. **Handle resolution**: extract handle from the preset's auth location (`Authorization: Bearer`, `x-api-key`, `X-Usk-Handle`, or query param for presets that need it). `BLAKE3(handle)` → constant-time lookup. Miss → 401 `unknown_handle` (same timing as a revoked one).
3. **Caller context**: local = loopback + optional peer executable check; hosted = device id from signature. Check `handle.callers` binding.
4. **Policy evaluation** (below). Result: `Allow`, `Deny(reason)`, `NeedsApproval(scope)`.
5. **Approval** (if needed): create approval request, push to owner, wait ≤ 120 s. Owner's decision may be cached per policy (`first_use`).
6. **Credential materialization**: decrypt secret (or take from hosted cache), build upstream request per preset adapter:
   - `bearer`: `Authorization: Bearer <secret>`
   - `header`: `<name>: <secret>` (e.g. `x-api-key` for Anthropic)
   - `basic`: `Authorization: Basic base64(user:pass)`
   - `query`: `?key=<secret>` (Google AI); logged as `query_auth` risk in the audit
   - `aws_sigv4`: sign with access/secret key (Phase 2)
   - `oauth2`: use cached access token; refresh with client secret + refresh token when expiring (Phase 2)
   - `template`: replace `{{usk:name}}` occurrences in URL, headers, body
7. **Host lock**: final upstream host must be in the secret's `upstreams` list (exact host match, or `*.example.com` if configured). Else 403 `host_not_allowed`. The route's preset upstream is used for presets; `X-Usk-Upstream` for generic.
8. **Egress guard**: scan the outgoing body and headers for the plaintext of *any other* stored secret (Aho-Corasick over all unlocked secret values ≥ 12 bytes, plus their base64 and URL-encoded forms). Hit → 403 `egress_blocked` + audit + notification.
9. **Forward**: HTTP/1.1 and HTTP/2 via `hyper`/`reqwest`; TLS via `rustls` with system roots; 30 s connect timeout; response streamed.
10. **Scrub**: response headers and body scanned for stored secret values; replaced by `[REDACTED:usk:<name>]`. For streams, keep a trailing buffer of `max_secret_len − 1` bytes to catch values that straddle chunks.
11. **Audit**: append `use` event (or `deny`, `egress_blocked`, `approval_*`) **before** returning the first response byte. Audit failure → 500 and the request is not forwarded (if the failure is detected before forwarding) or the response is dropped (if after; we accept this because INV-4 outranks availability).
12. **Response** to the caller with the pass-through status code and headers (minus hop-by-hop and minus any `Set-Cookie` from upstream by default).

## Header hygiene

- Strip from the incoming request before forwarding: `Authorization` (replaced), `X-Usk-*`, `Cookie`, `Host` (rewritten), hop-by-hop.
- Add: `User-Agent` passthrough (or `unseenkey/<ver>` if absent), `X-Request-Id` (also written to the audit event for correlation).
- Never add any header revealing owner identity to the upstream.

## Streaming

- SSE and chunked responses are forwarded chunk-by-chunk; scrubbing runs on the byte stream (no JSON parsing needed).
- Request streaming (large uploads) is supported for presets that mark `stream_body: true`; egress guard then scans the streamed body with the same overlap technique.
- WebSockets: not in MVP; return 501 with an explanation.

## Presets

A preset is a small TOML file compiled into the binary (and overridable in `~/.unseenkey/presets/`):

```toml
id = "openai"
display = "OpenAI"
upstreams = ["api.openai.com"]
auth = { kind = "bearer" }
detect = ["^sk-[A-Za-z0-9_-]{20,}$", "^sk-proj-"]
docs = "https://platform.openai.com/api-keys"

[[policies]]
id = "chat"
display = "Chat and embeddings only"
allow = ["POST /v1/chat/completions", "POST /v1/responses", "POST /v1/embeddings", "GET /v1/models"]

[[policies]]
id = "no-billing"
display = "Everything except org/billing/admin"
allow = ["* /v1/**"]
deny  = ["* /v1/organization/**", "* /v1/fine_tuning/**"]

[[policies]]
id = "full"
display = "Full access (not recommended for delegation)"
allow = ["* /**"]
```

Shipping presets in Phase 1: openai, anthropic, google-ai, mistral, groq, openrouter, stripe, github, supabase, vercel, resend, sendgrid, twilio, slack, notion, cloudflare, generic.

## Policy schema

```yaml
version: 1
secret: stripe-live                 # by name (resolved to id at save time)
upstreams: ["api.stripe.com"]       # inherited from secret; may only narrow
allow:                              # "<METHOD|*> <path-glob>"
  - "GET /v1/**"
  - "POST /v1/payment_intents"
  - "POST /v1/payment_intents/*/confirm"
deny:                               # evaluated after allow; deny wins
  - "POST /v1/refunds"
  - "* /v1/payouts/**"
limits:
  requests_per_minute: 120
  requests_per_day: 5000
  requests_total: 100000            # lifetime of the handle
  max_body_bytes: 1048576
schedule:                           # optional; UTC or IANA zone
  timezone: "Asia/Kolkata"
  allowed: ["Mon-Fri 09:00-19:00"]
expires_at: "2026-12-31T00:00:00Z"
approval:
  mode: none                        # none | first_use | every_use | paths
  paths: ["POST /v1/transfers/**"]  # when mode = paths
  timeout_seconds: 120
callers: ["device:2f9c…"]           # empty = any registered caller of this vault
injection: false                    # allow `usk run` env injection
mcp: true                           # expose to MCP clients
notes: "For the checkout project, Sept–Dec 2026"
```

### Evaluation rules

- Default deny. Unknown top-level keys → policy invalid → deny (INV-5).
- Path globs: `*` matches one segment, `**` matches any number; query strings are ignored for matching but logged.
- `deny` overrides `allow`.
- Limits are enforced with a sliding window in memory (local) or Redis (hosted). `requests_total` is persisted.
- `approval.mode: first_use` caches the owner's decision per `(handle, method, path-pattern)` until revoked.
- The engine is pure: `evaluate(policy, request_summary, caller, now) -> Decision`. No I/O, fully unit-testable, fuzzable.

### Policy presets vs. custom

The UI always starts from a preset. A custom policy is validated and rendered back as plain English ("Can read everything, can create payments, cannot refund, max 120/min, expires 31 Dec") so an owner without technical background can confirm what they are granting.

## Egress guard and scrubber details

- Build an Aho-Corasick automaton over all secret values on unlock and rebuild on change. Values shorter than 12 bytes are excluded (too many false positives) and flagged in the UI as "too short to guard".
- Also match `base64(value)`, `urlencode(value)`, and JSON-escaped forms.
- Scrubber replacement keeps the JSON valid where possible by replacing inside string literals; otherwise plain replacement.
- False positive path: if a legitimate response contains a stored value (e.g. the user stored their own account id as a secret), the owner sees `[REDACTED:usk:name]` and can mark the secret as `no_scrub`.

## Injection mode (`usk run`)

```
usk run --with OPENAI_API_KEY=openai --with DATABASE_URL=prod-db -- npm start
```

- Requires `injection: true` on each secret's policy and an unlocked vault.
- Spawns the child with the env vars set; stdout/stderr pass through the scrubber; writes an `inject` audit event listing secret names (not values).
- On Linux/macOS the env is set only for the child (not exported to the shell). Warn if the child is a shell.

## MCP server

Transports: stdio (`usk mcp`) and streamable HTTP (`/mcp` on uskd). Each MCP client gets its own token and caller identity (`mcp:claude-desktop`, `mcp:cursor`), so policies can differ per tool.

Tools:

| Tool | Input | Output |
|---|---|---|
| `list_secrets` | `{filter?}` | `[ {name, type, provider, policy_summary, mcp_enabled} ]` — never values |
| `call_api` | `{secret, method, path, headers?, body?, upstream?}` | `{status, headers(whitelist), body(scrubbed, ≤ 256 KiB, truncated flag)}` |
| `request_access` | `{secret, reason, scope?}` | `{approval_id, status}` — asks the owner to grant or widen policy |
| `explain_policy` | `{secret}` | Plain-English policy for this caller |
| `store_secret` | `{name, value, provider?}` | `{ok}` — lets an agent move a key it found in a file into the vault; value is never echoed. Off by default |

Resources: `usk://audit/recent` (last 50 events for this caller), `usk://presets`.

Prompts: `setup-project` (guides an agent to replace `.env` keys with handles), `delegate-check` (helps an owner verify a grant).

Safety rules baked in:
- The server's tool descriptions instruct the model that values are never available and it should not attempt to extract them.
- `call_api` upstream override is only allowed for `generic` secrets with matching `upstreams`.
- Every tool call is an audit event with the MCP client identity.

## Error responses

JSON body `{ "error": "<code>", "message": "<human>", "request_id": "…" }`. Codes: `browser_origin_rejected`, `unknown_handle`, `handle_revoked`, `handle_expired`, `vault_locked`, `policy_denied`, `host_not_allowed`, `egress_blocked`, `approval_required`, `approval_timeout`, `approval_denied`, `rate_limited`, `caller_not_allowed`, `upstream_error`, `audit_failure`. Messages never include the secret, the full policy (for grantees) or the upstream auth header.

## Performance notes

- Handle lookup: in-memory `HashMap<[u8;32], HandleRecord>`; constant-time compare of the 32-byte hash.
- Decrypt per request: XChaCha20-Poly1305 on a ≤ 4 KiB value is ~µs. Optional per-handle plaintext cache (≤ 60 s) behind a feature flag for hot paths; off by default locally, on by default hosted.
- Scrubber: Aho-Corasick DFA; throughput > 1 GB/s; negligible.
