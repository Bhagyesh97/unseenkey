# 13 — Operations

Covers running the local daemon well, deploying the cloud (Phase 3+), and responding to incidents.

## Local daemon operations

- **Install locations:** binaries in the package manager's path; data in `~/.unseenkey/` (macOS/Linux) or `%APPDATA%\Unseenkey\` (Windows), permissions 0700 / owner-only ACL.
- **Start:** `usk` starts `uskd` on demand; desktop app supervises it; optional login item (`usk service install`).
- **Upgrade:** `usk` and `uskd` must match versions; `usk` restarts `uskd` after upgrade; vault format migrations run on unlock with an automatic backup `vault.db.bak-<version>`.
- **Backup:** the vault file is safe to copy anywhere; recommend the user's normal backup plus the recovery kit. `usk export` for portable encrypted archives.
- **Diagnostics:** `usk doctor` checks: daemon reachable, port conflicts, token file permissions, clock skew, env vars pointing at the broker, MCP configs present, presets up to date, disk space for audit log.
- **Logs:** `~/.unseenkey/logs/uskd.log`, rotated at 10 MB × 5; redacting layer always on; `--log-level debug` never logs bodies.
- **Audit log growth:** ~300 bytes per event; 1M events ≈ 300 MB. `usk log prune --before 1y --keep-checkpoints` compacts while preserving chain checkpoints.

## Repository and releases

- **Public repository settings** (public since 2026-10-22; all of these are set): private vulnerability reporting on; secret scanning and push protection on; Dependabot alerts on; Actions allowed only from GitHub-owned actions and the namespaces the workflows use (`dtolnay/*`, `taiki-e/*`, `sigstore/*`, `anchore/*`, `tauri-apps/*`, `Swatinem/*`, `EmbarkStudios/*`, `softprops/*`); `main` protected against force pushes and deletion. Required status checks are deliberately not on yet: work lands by direct push, and a required check would refuse every push until the work moves to pull requests, at which point `ci` and `desktop` become required. The `TAURI_SIGNING_PRIVATE_KEY` secret stays; Apple and Authenticode secrets are added when certificates exist.
- **Never in the repository:** customer or interview material, the competitive survey (it names individuals), signing keys, anything from `%APPDATA%\Unseenkey`. The ignored `private/` directory is the place for local notes. Before the first public push, the history is checked for secrets and personal paths (`git grep` over `git rev-list --all`).
- **Releases:** a `v*` tag triggers `release.yml`: version check, CLI archives for five targets with Sigstore signatures, SBOM, desktop installers with minisign signatures and `latest.json` for the updater; hyphenated tags are pre-releases. The draft is published by hand after the installers have been smoke-tested on one machine per OS. After publishing, three manifests need the new version and hashes from `SHA256SUMS`: the Scoop bucket (`Bhagyesh97/scoop-unseenkey`, `bucket/usk.json`), the Homebrew tap (`Bhagyesh97/homebrew-unseenkey`, `Formula/usk.rb`) and a winget pull request (`microsoft/winget-pkgs`, `manifests/u/Unseenkey/Unseenkey/<version>/`, `InstallerType: wix`, `Scope: machine`, the MSI's `ProductCode`; `winget validate` before opening it).
- **Known advisories, accepted for now** (re-checked on every `cargo audit` of `apps/desktop/src-tauri/Cargo.lock`): `zip` 4.x (RUSTSEC-2026-0367/0368/0369, symlink and permission handling in `extract`) comes through `tauri-plugin-updater`, whose stable releases up to 2.14 require `zip ^4` on Windows and whose `zip` feature also provides the tar/gzip support macOS and Linux updates need. The updater unpacks a bundle only after its minisign signature verified, so exploiting these needs our signing key; move to the plugin's next major when it ships with `zip` 9. `glib` 0.18 (RUSTSEC-2024-0429, Linux only, iterator unsoundness in an API we do not call) is pinned by the gtk version Tauri 2 requires.
- **Secret-scanning partnership:** register the camouflage handle formats (every one contains `usk`) with GitHub's secret-scanning partner programme so a leaked handle is reported and revoked (runbook below). The programme needs an HTTPS endpoint that receives signed match reports, which is the `cloud-scan` service of M3.3; until it exists, a leaked handle is still harmless (it only works through the owner's broker), it just is not reported.

## Website (unseenkey.com)

- **Hosting:** Cloudflare Pages, project `unseenkey` (direct upload), custom domains `unseenkey.com` and `www`, KV namespace `WAITLIST` bound for the waitlist function, Email Routing for `security@` and `hello@`. The zone lives in the owner's Cloudflare account; ids are in `private/cloudflare-state.json`.
- **Set up and operated through Unseenkey itself:** the Cloudflare API token is a secret in the owner's vault (`cloudflare`, locked to `api.cloudflare.com`, injection allowed). Configuration calls go through the broker with a handle scoped by `private/cloudflare-site-policy.toml` (`private/cloudflare-setup.py`, idempotent); deploys run `usk run --with CLOUDFLARE_API_TOKEN=cloudflare -- node node_modules/wrangler/bin/wrangler.js pages deploy` from `site/`, because Wrangler's asset uploads use a one-off upload token that the broker cannot stand in for. Every call is in `usk log` under the `site ops` handle.
- **Continuous deploys:** `.github/workflows/site.yml` deploys on pushes to `site/**` once the repository secrets `CLOUDFLARE_API_TOKEN` (Pages: Edit only) and `CLOUDFLARE_ACCOUNT_ID` exist; until then it skips itself.
- **Changing the site:** edit `site/src` or `site/public`, `cd site && npm run build`, commit; deploy by push (with the secrets) or by the `usk run` line above.

## Cloud deployment (Phase 3)

### Topology

- Regions: start with one (e.g. `eu-central`), add `us-east` and `ap-south`; brokers are regional, accounts/sync global with regional read replicas.
- Each service is a stateless container behind a load balancer; Postgres managed (RDS/Neon/Supabase-Postgres), Redis or NATS for pub/sub, S3-compatible object storage for large sync blobs.
- Secrets for the services themselves (DB URLs, KMS roles) come from the cloud provider's IAM roles, never from files. We dogfood Unseenkey for third-party keys we use.

### Hosted broker specifics

- Stateless; loads grant envelopes from `sync` on first use, caches plaintext ≤ `cache_ttl` in memory only; revocation via pub/sub invalidates caches within 1 s.
- KMS: envelope decryption key in AWS KMS (Phase 3); the broker service role is the only principal with `Decrypt`; CloudTrail on every call.
- Phase 4: the broker runs inside a Nitro Enclave; the parent instance only proxies bytes; KMS key policy requires the enclave's PCR0 (attestation-gated decrypt).
- Rate limiting and WAF at the edge; per-grant limits inside.
- Health: `/healthz` (liveness), `/readyz` (KMS reachable, pub/sub connected).

### Observability

- Metrics (Prometheus): requests by preset/status, latency histograms, policy denials, egress blocks, approval latency, cache hit rate, KMS latency.
- Traces (OpenTelemetry) with request ids; **no headers or bodies as attributes**.
- Logs structured JSON, redacting layer, 30-day retention, no secret material by design.
- Alerts: error rate > 1%, p99 > 200 ms, KMS failures, audit write failures (page immediately), spike in `unknown_handle` (credential stuffing).

### Availability targets

| Service | SLO |
|---|---|
| Hosted broker | 99.9% (Phase 3) → 99.95% (Phase 4) |
| Sync/accounts | 99.9% |
| Events/push | 99.5% |

Per-grant `fail_mode`: `closed` (default) or `open` (serve from cached policy and cached plaintext for up to N minutes if control plane is down; plaintext cache must already be warm). Owners choose; UI explains.

### Backups and DR

- Postgres PITR, 30 days; daily snapshots to a second region.
- Sync records are ciphertext, so backups are low-sensitivity; grant envelopes are decryptable only with KMS in the origin region; DR region has its own KMS key and envelopes are re-created by owners' clients on region failover (clients re-encrypt to the new broker key on next sync).
- Quarterly restore drill.

## Self-hosting

`deploy/docker-compose.yml` runs all cloud services with a local Postgres and MinIO; `USK_KMS=local` uses a file-based key for development only, with a loud warning; production self-hosters use their cloud KMS or an HSM via PKCS#11 (Phase 4). Helm chart in Phase 4.

## Incident response

### Severity

| Sev | Definition | Response |
|---|---|---|
| S1 | Plaintext secret exposure possible or confirmed | All hands; public disclosure within 72 h; affected owners notified within 24 h with the list of secrets to rotate; one-click rotate where adapters exist |
| S2 | Policy bypass, audit integrity failure, auth bypass without plaintext exposure | Fix and release within 48 h; disclosure in release notes |
| S3 | Availability or non-security bugs | Normal process |

### Runbook: suspected plaintext exposure

1. Freeze deploys; snapshot affected systems.
2. Determine scope: which grants/vaults, which time window, from audit and KMS logs.
3. Revoke affected broker keys; owners' clients re-encrypt envelopes to the new key automatically.
4. Notify owners in-app and by email with exact secret names; trigger rotation prompts.
5. Root cause, fix, regression test, post-mortem published.

### Runbook: leaked handle report (from GitHub scanning or user)

1. `cloud-scan` receives handle hash → mark revoked → pub/sub invalidate.
2. Notify the owner with source and timestamp; suggest creating a new handle.
3. No secret rotation needed (the handle alone is useless), but offer it.

### Runbook: local daemon vulnerability

1. Ship a patched release; auto-updater and package managers.
2. `usk doctor` flags outdated versions; desktop shows a banner.

## Compliance groundwork (Phase 3–4)

- Data map: what is stored where; ciphertext vs cleartext columns (from [08](08-data-model.md)).
- GDPR: account deletion removes accounts, devices, sync records, grants, audit events after a 30-day tombstone; owners can export everything.
- Retention: audit events kept while the grant/vault exists plus 1 year, configurable.
- SOC 2 controls mapped to CI gates, access reviews, incident runbooks.
