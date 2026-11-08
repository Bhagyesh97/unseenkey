# 07 — Broker, Policy Engine and MCP Server

The broker is the heart of the product. It is the only component that turns a handle into a real credential, and it does so for one outgoing request at a time.

## Routes

| Route | Purpose | Auth |
|---|---|---|
| `/p/<preset>/<path…>` | Base-URL proxy for a known provider (e.g. `/p/openai/v1/chat/completions`) | Handle in the provider's usual header |
| `/p/generic/<path…>` | Proxy to any upstream named in `X-Usk-Upstream`, with template substitution | Handle in `X-Usk-Handle` or templates in request |
| `/p/<preset>/@<host>/<path…>` | The upstream named in the URL instead of a header, for SDKs that can change their base URL but cannot add headers (AWS per-service endpoints, Supabase). Same host lock as the header | As for the preset |
| `/v1/*` | Management API (vault, handles, policies, audit) | Session token |
| `/mcp` | MCP streamable HTTP | Session token or per-client MCP token |
| `/healthz` | Liveness | none (no info beyond `ok`) |

## Request pipeline (local and hosted share this code)

1. **Ingress checks**
   - Local: reject if `Origin`, `Referer`, `Sec-Fetch-Site`, `Sec-Fetch-Dest`, `Sec-Fetch-User` or `Sec-CH-UA` is present → 403 `browser_origin_rejected`. `Sec-Fetch-Mode` alone is **not** a marker: Node's `fetch` (undici), hence the OpenAI/Anthropic Node SDKs and Claude Code, sends `sec-fetch-mode: cors` on every request, while real browsers always add `Sec-Fetch-Site`/`Sec-Fetch-Dest` (and `Origin` cross-site) with it. Reject if `Host` is not `127.0.0.1:7391`/`localhost:7391`/`[::1]:7391`.
   - Hosted: verify TLS, device signature, timestamp, nonce.
   - Body size limit (default 32 MiB, streaming for larger where allowed).
2. **Handle resolution**: extract handle from the preset's auth location (`Authorization: Bearer`, `x-api-key`, `X-Usk-Handle`, or query param for presets that need it). `BLAKE3(handle)` → constant-time lookup. Miss → 401 `unknown_handle` (same timing as a revoked one).
3. **Caller context**: local = loopback + optional peer executable check; hosted = device id from signature. Check `handle.callers` binding.
4. **Policy evaluation** (below). Result: `Allow`, `Deny(reason)`, `NeedsApproval(scope)`.
5. **Approval** (if needed): create approval request, push to owner, wait ≤ 120 s. Owner's decision may be cached per policy (`first_use`).
6. **Credential materialization**: decrypt secret (or take from hosted cache), build upstream request per preset adapter:
   - `bearer`: `Authorization: Bearer <secret>`
   - `header`: `<name>: <secret>` (e.g. `x-api-key` for Anthropic)
   - `basic`: `Authorization: Basic base64(user:pass)` (see *Keys in two parts* below)
   - `query`: `?key=<secret>` (Google AI); logged as `query_auth` risk in the audit
   - `aws_sigv4`: sign the whole request with the secret access key (see *AWS* below)
   - `oauth2_client` secrets (any route): send a cached access token as `Authorization: Bearer`; refresh it with the stored refresh token when it is about to expire (see *OAuth2* below)
   - `template`: replace `{{usk:name}}` occurrences in URL, headers, body
7. **Host lock**: final upstream host must be in the secret's `upstreams` list (exact host match, or `*.example.com` if configured). Else 403 `host_not_allowed`. The route's preset upstream is used for presets; `X-Usk-Upstream` for generic. A provider with a host per customer has a further rule (see *Hosts per customer* below).
8. **Egress guard**: scan the outgoing body and headers for the plaintext of *any other* stored secret (Aho-Corasick over all unlocked secret values ≥ 12 bytes, plus their base64 and URL-encoded forms). Hit → 403 `egress_blocked` + audit + notification.
9. **Forward**: HTTP/1.1 and HTTP/2 via `hyper`/`reqwest`; TLS via `rustls` with system roots; 30 s connect timeout; response streamed.
10. **Scrub**: response headers and body scanned for stored secret values; replaced by `[REDACTED:usk:<name>]`. For streams, keep a trailing buffer of `max_secret_len − 1` bytes to catch values that straddle chunks.
11. **Audit**: append `use` event (or `deny`, `egress_blocked`, `approval_*`) **before** returning the first response byte. Audit failure → 500 and the request is not forwarded (if the failure is detected before forwarding) or the response is dropped (if after; we accept this because INV-4 outranks availability). A request with no answer recorded leaves a `use_unfinished` event with `why`: `locked` or `stopped` (written by the lock or stop itself, while it still has the key) or `caller_left`. It counts toward a handle's limits, and may have reached the provider. A request cut off by a crash still leaves nothing.
12. **Response** to the caller with the pass-through status code and headers (minus hop-by-hop and minus any `Set-Cookie` from upstream by default).

## AWS

AWS has no key to inject: every request is signed (SigV4) with the secret access key over the method, path, query, chosen headers and a hash of the body. So the SDK gets the handle as its *access key id* and any placeholder as its secret (`usk env <aws secret>` prints `AWS_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID=usk_h_…`, `AWS_SECRET_ACCESS_KEY=handled-by-unseenkey`). It signs with the placeholder. The broker:

1. takes the handle and the `<region>/<service>` scope out of the SDK's `Authorization: AWS4-HMAC-SHA256 Credential=…` header and discards the SDK's signature;
2. picks the endpoint: an explicit `X-Usk-Upstream` or `/p/aws/@<host>/…` if given, otherwise `<service>.<region>.amazonaws.com` with a short table of exceptions (`ses` → `email.…`, `ecr` → `api.ecr.…`, global `iam`/`route53`/`cloudfront`). Signing names that cover several endpoints or per-resource hosts (`bedrock`, `execute-api`, `es`, …) are refused with `aws_host_required` and need the `@<host>` form;
3. runs the usual host lock and policy on that host;
4. undoes `aws-chunked` upload framing (its per-chunk signatures were made with the placeholder), turning a trailing checksum into an ordinary header;
5. sets `x-amz-date` from its own clock, `x-amz-content-sha256` to the exact body hash, `x-amz-security-token` from the stored session token if there is one, and signs `host`, `content-type` and every `x-amz-*` header with the real key (`core::broker::sigv4`).

Without an SDK (curl, MCP `call_api` with `upstream=`), the handle travels in `X-Usk-Handle` and the scope is worked out from the host name.

What a key may do inside AWS is IAM's business. The broker adds a coarser fence in front: which endpoints (so which services and regions) a handle reaches, and for S3, which methods and paths. Host patterns may use a `*` label for exactly one label (`s3.*.amazonaws.com`); preset policies can narrow the preset's hosts. `GET` is only treated as read-only for S3, because query-protocol services accept state-changing actions in a GET. The audit `use` event carries `aws: "<service>/<region>"` and, for JSON and query protocols, `action` (`DynamoDB_20120810.GetItem`, `SendMessage`). Rules on those actions are not implemented yet.

Not supported: SigV4A (multi-region access points; refused with `sigv4a_unsupported`), presigned URLs (they are made client-side, with the placeholder), and S3 object keys containing `.` or `..` path segments (the HTTP client normalises them away).

Verification: `tests/vectors/sigv4.json` is generated with botocore and checked byte for byte (canonical request and signature); `crates/daemon/tests/aws_interop.rs` runs boto3 through the broker against a stand-in that re-verifies every signature with botocore (CI job `aws-interop`).

## OAuth2

A secret of kind `oauth2_client` holds a refresh token (the value) with fields `client_id`, `token_url` and optionally `client_secret`, `scope`, `token_auth` (`basic` to authenticate the client with HTTP Basic instead of form fields). The caller presents a handle wherever an access token would go (`Authorization: Bearer usk_h_…`), on a preset route or on `/p/generic/@<api host>/…`. The broker keeps one access token per secret in memory, refreshes it 60 seconds before the stated expiry (one refresh at a time), and sends that upstream. The caller never sees either token: the access token joins the scrubber's guarded values the moment it is obtained (`[REDACTED:usk:<name>.access_token]`).

- The token endpoint is a second destination for the secret, so its host must be in the secret's own `upstreams` (added automatically when the secret is stored). A handle's policy may narrow where the *handle* goes without affecting where the secret refreshes; taking the token host off the secret makes refreshing fail with `host_not_allowed`.
- A rotated refresh token in the provider's answer is written to the vault as a new version (audit `secret_updated`, reason `oauth_rotation`). If that write fails the request fails with `oauth_rotation_failed`, because the old refresh token may already be dead.
- A refused refresh is answered with 502 `oauth_refresh_failed` carrying the provider's `error` and `error_description` (scrubbed), is audited, and is not cached.
- Access tokens are forgotten on lock and when the secret's value changes.
- Adding: paste or pipe the JSON OAuth tooling writes (`client_id`, `client_secret`, `refresh_token`, `token_uri`); gcloud's `application_default_credentials.json` needs nothing more, its token endpoint and `*.googleapis.com` are implied. `usk add <name> --type oauth2_client --upstream <api host>` asks for the four values instead.

Not done: obtaining the first refresh token (the authorization-code dance) and client-credentials grants.

## Keys in two parts

A preset with `auth = { kind = "basic", username_label = "…", secret_label = "…" }` wants two values. The stored value is the password and field `username` the other part, with kind `basic_auth`. A preset with `username = "api"` has the same username for everybody and takes one value; `username = ""` sends the key alone.

- Adding: `usk add` asks for each part in the provider's words (from the name or `--provider` before the first prompt, from the shape of the first part otherwise). The app shows a second box. `first:second` or two lines are taken apart by the daemon, at the first colon, so a username cannot hold one. `usk import` and `usk guard fix` join a preset's `env.api_key` and `env.username` variables into one secret.
- One part stored: allowed, since `usk import` meets them one at a time. Nothing is sent: a call answers 400 `secret_shape` and the key test says what is missing. `usk secret set <name> --username …` (`PATCH` with `username`) adds it.
- Replacing the password keeps the username. Two lines replace both parts. One line with a colon is the whole new password, unless what precedes the colon is the stored username: a password's first half must not land in a field the scrubber leaves alone.
- A Basic route only serves its own provider's secrets (400 `route_mismatch` otherwise), because the guard for the header is built from the secret's provider.
- The handle: `Authorization: Bearer <handle>`, or the `Basic` header an SDK builds with the handle as its secret (`base64(account:handle)`) or, where the key is the username, `base64(handle:)`.
- Scrubbing: the password, and `username:password` in all its encoded forms (so an echoed header is hidden). The username is not guarded: it is an account id or an email that providers put in their answers and paths. MCP's `list_secrets` shows it as `account`, for the paths that need it.
- The two parts apart: a preset's `username_like` says what its usernames look like (`AC*`, `*@*`; `*` any text, `?` one character). A pair pasted the wrong way round is put right when stored. If neither part fits, it is stored as given, because a provider may change its ids: the username is then treated as the secret it may be, so it is guarded and not shown as `account`, and the key test reports the refusal.
- A preset's `[verify]` path may hold `{username}`.

## Hosts per customer

Some providers give every customer a host of their own, and anyone can get one: a wildcard host lock would let a key go to a stranger's Supabase project or Atlassian site, where its owner can read it. A preset with `tenant = { label, example }` therefore never sends a key on the strength of a wildcard.

- Naming the host: `usk add` asks for it, the app has a box for it, and `--upstream` or `usk secret set <name> --upstream <host>` (owner only) sets it. `usk import` and `usk guard fix` read it from the preset's `env.base_url` variable, also with a prefix (`NEXT_PUBLIC_SUPABASE_URL`), if that URL is under the provider's hosts and its variable belongs with the key (`PROD_SUPABASE_KEY` takes `PROD_SUPABASE_URL`; `NEXT_PUBLIC_`, `VITE_` and the like do not count). Several hosts are allowed; list each one.
- Until then the key is stored but goes nowhere: `POST /v1/secrets` answers with `needs_host`, a call answers 403 `host_not_pinned` and is audited, and the key test says what to do. A wildcard of one of these providers counts as no host named, whatever provider the secret has or lacks. The example in messages (`<project-ref>.supabase.co`) is deliberately not a valid host: a real-looking name could be someone's.
- Once named, a call needs no `X-Usk-Upstream`: it goes to the first host named. A handle whose policy lists the provider's wildcard is narrowed to the owner's hosts.

The other wildcards stay: `*.amazonaws.com` receives signatures rather than keys, and `*.googleapis.com` receives short-lived tokens and is Google's own.

## Google service accounts

A secret of kind `gcp_service_account` holds a Google JSON key file (the value, whole, so `usk run` can still hand it to a tool that wants the file) with the fields `private_key` (so the scrubber guards the key by itself, including as a JSON string) and `scope` (space-separated). The caller presents a handle where an access token would go, on `/p/gcp/@<api host>/…` or `/p/generic/@<api host>/…`. There is no refresh token: the broker signs a one-hour JWT with the file's key (RS256, RFC 7523), trades it at the file's `token_uri` and handles the access token exactly as under *OAuth2*: one at a time, cached in memory, forgotten on lock and when the secret changes, guarded by the scrubber. The key file itself never travels, on any route.

- Adding: `usk add <name> --file key.json --scope webmasters.readonly` (`--scope` is repeatable; a bare name is short for `https://www.googleapis.com/auth/<name>`). The file is checked when added: `service_account_incomplete` without `client_email` and `private_key`, `invalid_private_key` if the key cannot sign. Hosts default to `*.googleapis.com`; the token endpoint's host joins the secret's list.
- Scopes are required to sign in but not to store: without them a call answers 400 `scope_required`, naming the fix. `usk secret set <name> --scope …` (`PATCH /v1/secrets/{ref}` with `scope`) replaces them. That widens what tokens may do, so it is owner only; it creates a new version, so the next call gets a new token.
- A refused sign-in is remembered for 5 seconds, doubling up to a minute, so that many callers make one attempt. A new value or scope, or the key test, tries again at once. The same holds for OAuth clients, which have no key test.
- `usk secret test` signs in afresh and reports what Google said. That proves the key and scopes, not what the account was added to; each API decides that.
- Replacing the value takes `usk rm` and `usk add`, as for the other kinds that hold several values.

`read-only` means GET: what a GET can reach depends on the scopes, so a key with `cloud-platform` could read Secret Manager under it. Choose narrow scopes.

Not done: domain-wide delegation (the `sub` claim) and adding scopes in the desktop app, which stores the pasted file and points at the command above.

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

```toml
# TOML when a human edits it, JSON when the vault stores it (D-11 amendment).
version = 1
secret = "stripe-live"                # by name (resolved to id at save time)
upstreams = ["api.stripe.com"]        # inherited from the secret; may only narrow
allow = [                             # "<METHOD|*> <path-glob>"
  "GET /v1/**",
  "POST /v1/payment_intents",
  "POST /v1/payment_intents/*/confirm",
]
deny = [                              # deny wins over allow
  "POST /v1/refunds",
  "* /v1/payouts/**",
]
expires_at = "2026-12-31T00:00:00Z"
callers = ["device:2f9c…"]            # empty = any registered caller of this vault
injection = false                     # allow `usk run` env injection
mcp = true                            # expose to MCP clients
notes = "For the checkout project, Sept–Dec 2026"

[limits]
requests_per_minute = 120
requests_per_day = 5000
requests_total = 100000               # lifetime of the handle
max_body_bytes = 1048576

[schedule]                            # optional; IANA zone
timezone = "Asia/Kolkata"
allowed = ["Mon-Fri 09:00-19:00"]

[approval]
mode = "none"                         # none | first_use | every_use | paths
paths = ["POST /v1/transfers/**"]     # when mode = paths
timeout_seconds = 120
```

`usk policy explain --file policy.toml` renders this as:

```
Can read anything under /v1, create or send at /v1/payment_intents, and create or send anything under /v1/payment_intents.
Cannot create or send at /v1/refunds and do anything under /v1/payouts.
Only to api.stripe.com.
At most 120 requests per minute, 5,000 per day, and 100,000 in total.
Requests larger than 1 MiB are refused.
Only Mon–Fri 09:00–19:00 (Asia/Kolkata).
Expires 31 Dec 2026 (UTC).
Usable only by device:2f9c….
Note: For the checkout project, Sept–Dec 2026
```

### Evaluation rules

- Default deny. Unknown top-level keys → policy invalid → deny (INV-5).
- Path globs: `*` matches one segment, `**` matches any number; query strings are ignored for matching but logged.
- `deny` overrides `allow`.
- Limits are enforced with a sliding window in memory (local) or Redis (hosted). Locally the windows are rebuilt from the last day of `use` audit events on unlock, so a restart does not reset them. `requests_total` is persisted every 100 uses and on lock; on unlock the vault adds back the `use` events written after the record's last flush, so a crash loses nothing.
- `approval.mode: first_use` caches the owner's decision per `(handle, method, path-pattern)` until revoked.
- The engine is pure: `evaluate(policy, request_summary, caller, now) -> Decision`. No I/O, fully unit-testable, fuzzable.

### Policy presets vs. custom

The UI always starts from a preset. A custom policy is validated and rendered back as plain English ("Can read everything, can create payments, cannot refund, max 120/min, expires 31 Dec") so an owner without technical background can confirm what they are granting.

## Template mode (secrets without a preset)

A secret with no provider, or any secret on the `generic` route, is placed by the caller: the handle travels in `X-Usk-Handle`, and `{{usk:<secret>}}` marks where the value goes, in the path, the query, a header or the body. The broker fills the placeholder in after the request passed the policy. Headers the broker normally strips because an SDK may have put a credential in them (`Authorization` first of all) are kept when they carry a placeholder, so `Authorization: Bearer {{usk:name}}` works. A stored value that cannot be a header value once filled in (a trailing newline, a control character) is refused with `malformed_request` naming the header rather than dropped.

## User presets

A provider the project does not ship can be added without a rebuild: `<vault dir>/presets/<id>.toml` in the same format as [`crates/core/presets/`](../crates/core/presets/) is loaded by the daemon at start and by the CLI on every run, beside the built-in presets; a file with a built-in id overrides it. Invalid files are skipped with a warning in the daemon log and on the CLI's stderr. `usk presets` marks them "(yours)".

## Egress guard and scrubber details

- Build an Aho-Corasick automaton over all secret values on unlock and rebuild on change. Values shorter than 12 bytes are excluded (too many false positives) and flagged in the UI as "too short to guard".
- Also match `base64(value)`, `urlencode(value)`, and JSON-escaped forms. A multi-line value over 256 bytes is matched by its lines of 32 bytes or more in streams, since a stream holds back the length of the longest pattern, and whole as well in anything held in one piece (requests, whole replies). With no such line it is matched whole everywhere.
- Scrubber replacement keeps the JSON valid where possible by replacing inside string literals; otherwise plain replacement.
- False positive path: if a legitimate response contains a stored value (e.g. the user stored their own account id as a secret), the owner sees `[REDACTED:usk:name]` and can mark the secret as `no_scrub`.

## Caps, canaries and unusual activity

A leaked key costs money until someone notices. A handle has three defences the key never had, all local and all explainable; none of them rotates the real key, which no provider lets us do safely.

**Caps.** `--cap 1000/day` and `--cap 60/min` on `usk handle create` and `usk env` (API: `cap_per_day`, `cap_per_minute`) write `limits.requests_per_day` / `requests_per_minute` into the handle's policy, replacing the preset's own figure. They are hard stops: the 1,001st request of the day is refused with `rate_limited` and nothing is sent upstream. Running into a cap is the cap doing its job; it is not an incident.

**Canaries.** `usk handle create <secret> --canary` makes a handle that never works: its policy is the empty one and the broker never looks the secret up for it. Plant it where only an intruder would read it (a `.env.example`, an old repository, a notes page; `--camouflage` makes it look like a real key). Any use at all is recorded as `canary_tripped`, the owner is told, and the handle's response runs: `lock` by default, since whoever sent it has the file. From outside, a canary answers exactly like an unknown handle (401 `unknown_handle`), so an intruder cannot tell it from a dead key. A canary only trips while the vault is unlocked: locked, every handle is refused before lookup.

**Denial bursts.** Ten policy refusals on one handle within a minute (`policy_denied`, `host_not_allowed`, `caller_not_allowed`, `outside_schedule`, `body_too_large`; not caps, not the handle's own standing) are an incident of kind `denial_burst`: a tool that keeps trying things the policy forbids is exploring, not working. At most one incident is raised per handle per hour; `resume` clears the hour.

**Responses.** Each handle carries `on_anomaly`, chosen at creation (`--on-anomaly`, API `on_anomaly`, changeable with `PATCH`), which the broker applies to a burst or a tripped canary:

| response | what happens | default for |
|---|---|---|
| `alert` | the `anomaly` audit event, the `anomaly` SSE event, a desktop notification; nothing else | |
| `throttle` | the same, and the handle gets at most 6 requests a minute for an hour (`throttled`, 429) | working handles |
| `approve` | every request on the handle waits for the owner, remembered rules notwithstanding, until resumed | |
| `pause` | the handle refuses everything (`handle_paused`, 403) until resumed | |
| `lock` | the vault locks (audit `lock` with reason `anomaly` or `canary`) | canaries |

The standing (`status`: `normal`, `throttled` with `until`, `approval_required`, `paused`) and the incident behind it (`last_anomaly`: kind, detail, time, response) live in the handle record, so they survive a restart and show in `usk handle show`, `usk handle ls` and the desktop. `usk handle resume <handle>` (`POST /v1/handles/{id}/resume`) puts the handle back to normal and restarts its burst detector; a throttle also ends by itself after the hour. The desktop app offers "Back to normal" on the handle and a drop-down for the response.

What this does not do yet: baselines ("5× the usual volume for this hour"), first-seen endpoints or models, spend in currency, and binding a handle to the process that may use it. Those are the next slices; this one makes the simplest claims true: a leaked handle cannot run up a bill past its cap, a planted canary tells you the moment someone has your files, and a tool that probes gets slowed, stopped or asked.

## Care levels

The policy Unseenkey hands out by itself, to an MCP client on its first use of a secret or to a handle created without a policy, comes from `presets::policy_for(preset, care)`:

| Level | Policy |
|---|---|
| `relaxed` | allow `* /**`; approval (`mode = paths`) for `DELETE /**` and the preset's money-out rules (refund, payout, transfer, withdraw, disburse, top-up) |
| `balanced` (default) | allow `* /**`; approval for the preset's `ask_first` rules, or deletes plus the deny rules of its non-`full` policies |
| `strict` | the preset's recommended policy |

The policy's own host list is left empty, so the secret's host lock decides where it may go. Such handles carry `follows_care`; changing the level rewrites their policy (keeping callers, limits, expiry and remembered answers). Editing a handle's policy clears the flag. Handles from before the flag whose label is `mcp:…` and whose rules still equal the strict default are treated as following. Host locks, the scrubber, the egress guard and the audit log do not depend on the level.

## Recognising and testing a pasted key

Order of evidence, strongest first: the value's shape (`providers::detect`), a `key_prefixes` entry only one preset claims (`presets::detect_by_prefix`; prefixes under four characters or shared by two presets never decide), then the secret's name (`presets::guess_by_name`: an exact variable from `[env]`/`env_names`, or a word equal to a preset id or display name). Recognition sends nothing anywhere.

A preset's `[verify]` names one read-only request (`method`, `path`, optional `host` and non-secret `headers`), and `also_path` for a provider with two kinds of key and no one address that takes both, as with Cloudflare's user and account tokens: refused means refused by the first and 401 from the second, because 403 there can mean a good key without permission for that address. Test paths must start with `/`; a preset with one that does not is not loaded, because a test URL is the host followed by the path. The test sends the key only there, only when that host is within the secret's locked upstreams, with the preset's auth style; 2xx reads as accepted, 401/403 as refused, anything else as unclear. A key is never tried against several providers to find out whose it is: that would hand the key to companies it does not belong to.

Hosts hold only letters, digits, `.`, `-` and `_` (an IPv6 address in brackets), because a URL parser may read anything else as the end of the host; the request goes only to the host the lock judged. Policies judge the path as it will be sent: `..` and `%2e%2e` resolved, `\\` as `/`, characters that never need encoding decoded (`%6Beys` is `keys`). `%2F` stays encoded, a `..` next to one is refused, and deny rules hold in any letter case. `X-HTTP-Method-Override` and its relatives never travel. A `*` inside a path segment (`*.json`) matches within that segment.

Auth styles: `bearer`, `header`, `scheme` (`Authorization: <scheme> <key>`), `basic`, `query`, `template`, `aws_sigv4`.

## Projects

A project names the code folders of one app and the secrets it uses; a secret can be in several. It is an encrypted `project` record (name, normalised folders, secret ids, `cap_per_day`, notes). Two things follow from it:

- **Agent scope.** An MCP client whose reported folder falls inside a project's folder (the deepest match wins) sees and uses only that project's secrets; see the MCP section.
- **A daily limit per project.** Handles may carry the project they were made for (`usk project protect`, `usk guard fix --project`, `usk handle create --project`, and MCP handles created inside the folder). After the host lock and before policy evaluation, the broker sums the last 24 hours of requests across the project's handles; at `cap_per_day` it answers `429 project_cap_reached` and audits a `deny` with `reason: project_cap`. Handles not made for the project are not counted or held back.

Deleting a secret takes it out of every project. Deleting a project keeps its secrets and handles; the handles stop counting toward any limit.

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
| `request_access` | `{secret, reason, scope?, upstream?}` | `{approval_id, status}` — asks the owner to approve a gated path and/or allow a host the secret is not locked to; approval adds the host to the secret |
| `explain_policy` | `{secret}` | Plain-English policy for this caller |
| `store_secret` | `{name, value, provider?}` | `{ok}` — lets an agent move a key it found in a file into the vault; value is never echoed. Off by default |

Resources: `usk://audit/recent` (last 50 events for this caller), `usk://presets`.

Prompts: `setup-project` (guides an agent to replace `.env` keys with handles), `delegate-check` (helps an owner verify a grant).

Safety rules baked in:
- The server's tool descriptions instruct the model that values are never available and it should not attempt to extract them.
- `call_api` upstream override is only allowed for `generic` secrets with matching `upstreams`.
- Every tool call is an audit event with the MCP client identity.

## Error responses

JSON body `{ "error": "<code>", "message": "<human>", "request_id": "…" }`. Codes: `browser_origin_rejected`, `unknown_handle`, `handle_revoked`, `handle_expired`, `vault_locked`, `policy_denied`, `host_not_allowed`, `egress_blocked`, `approval_required`, `approval_timeout`, `approval_denied`, `rate_limited`, `throttled`, `handle_paused`, `caller_not_allowed`, `upstream_error`, `audit_failure`. Messages never include the secret, the full policy (for grantees) or the upstream auth header.

## Performance notes

- Handle lookup: in-memory `HashMap<[u8;32], HandleRecord>`; constant-time compare of the 32-byte hash.
- Decrypt per request: XChaCha20-Poly1305 on a ≤ 4 KiB value is ~µs. Optional per-handle plaintext cache (≤ 60 s) behind a feature flag for hot paths; off by default locally, on by default hosted.
- Scrubber: Aho-Corasick DFA; throughput > 1 GB/s; negligible.
