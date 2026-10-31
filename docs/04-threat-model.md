# 04 — Threat Model

Read this before writing any code that touches a secret. Every mitigation here maps to a test in [12](12-testing-and-assurance.md).

## Assets

| Asset | Sensitivity |
|---|---|
| A1. Secret plaintext (keys, tokens, passwords) | Critical |
| A2. Vault master key and derived keys | Critical |
| A3. User password / passkey material | Critical |
| A4. Handles and grants (capabilities) | High: usable with a registered caller |
| A5. Policies (what a grantee may do) | High: tampering enables misuse |
| A6. Audit log | High: integrity matters more than confidentiality |
| A7. Metadata (secret names, providers, usage patterns) | Medium: reveals what a user has |
| A8. Broker private key (delegation mode) | Critical |
| A9. Source code and release pipeline | Critical (supply chain) |

## Adversaries

| ID | Adversary | Capability |
|---|---|---|
| T1 | **Careless self** | Pastes things into chat, commits files, screenshots |
| T2 | **Prompt-injected agent** | Executes attacker instructions with the agent's tools: reads files, calls APIs, sends data anywhere the agent can reach |
| T3 | **Malicious web page** | Can issue requests to localhost from the user's browser; DNS rebinding |
| T4 | **Other local process (same user)** | Reads files the user can read, connects to loopback, may read process memory depending on OS |
| T5 | **Malicious grantee (Dev)** | Controls their own machine entirely; wants the plaintext or to exceed policy |
| T6 | **Network attacker** | Observes/alters traffic between components |
| T7 | **Cloud operator (us) or a compromised cloud** | Reads databases, disks, logs; a rogue employee; a subpoena |
| T8 | **Attacker with a stolen device** | Offline access to disk; maybe a running unlocked session |
| T9 | **Supply-chain attacker** | Compromises a dependency, our build, or our update channel |
| T10 | **Upstream API** | The provider itself echoes secrets or is compromised |

## Trust boundaries

```
┌───────────────────────── User's machine ─────────────────────────┐
│  Browser tabs (T3)      Agents / IDEs (T2)     Other procs (T4)  │
│        │                       │                     │           │
│        ▼                       ▼                     ▼           │
│   ══════════════ loopback boundary (Origin/Sec-Fetch checks) ═════│
│                       Unseenkey daemon                            │
│   ┌──────────┐  ┌────────────┐  ┌────────┐  ┌───────────┐        │
│   │ vault    │  │ broker     │  │ policy │  │ audit log │        │
│   │ (crypto) │  │ (proxy)    │  │ engine │  │ (chained) │        │
│   └──────────┘  └────────────┘  └────────┘  └───────────┘        │
│        ▲ encrypted at rest (T8)                                  │
└────────┼──────────────────────────────┬──────────────────────────┘
         │ E2E-encrypted sync (T6, T7)  │ TLS to upstream (T6, T10)
         ▼                              ▼
┌──────────────────┐            ┌──────────────┐
│ Unseenkey cloud   │            │ api.stripe…  │
│ relay/sync (T7)  │            └──────────────┘
│ hosted broker    │ ◀── requests from grantee devices (T5)
│ (KMS → enclave)  │
└──────────────────┘
```

## Threats and mitigations

### Self mode

| Threat | Mitigation | Residual |
|---|---|---|
| T1 pastes a key into chat | The key is never displayed after storage; handles are what users copy; `.env` guard replaces real keys with handles | User can still `usk reveal` intentionally (logged, requires unlock) |
| T1 commits `.env` | `.env` guard; docs push base-URL pattern; handles are safe to commit | None significant |
| T2 asks the agent to `curl` with `{{usk:x}}` to attacker host | Host lock: substitution only for the secret's upstream | Attacker can still call the *legitimate* upstream within policy (power problem) |
| T2 makes the agent exfiltrate a secret it read from somewhere | Egress guard scans bodies to non-upstream hosts for stored values | Encoded/obfuscated exfil not caught; agent could read `.env` if user still has plaintext elsewhere |
| T2 uses `usk run` to get plaintext | `allow_injection` off by default; injection audited; output scrubbed | Base64/transforms defeat scrubbing; documented weaker mode |
| T2 has a shell and reads `daemon.token` | The session token covers reading metadata, adding keys and care-level handles only. Revealing a value, injecting, approving a request, enrolling an unlock method, changing the care level or idle lock, and naming or changing a policy need an **owner token**: issued by `POST /v1/unlock` and `POST /v1/confirm` against the password or a device unlock, held in the CLI's or app's memory, cleared on lock, never on disk | The agent can still do everything the care level allows, and anything the owner confirms; a process that reads the app's memory is T4 |
| T2 approves its own request | Approvals are owner-only (above); `approve latest` is refused when more than one request is waiting, so a request slipped in at the last moment cannot ride on the owner's answer | None significant |
| T2 calls `list_secrets` | Returns metadata only | Metadata reveals what the user has (A7); acceptable |
| T2/T4 registers an MCP identity of its own (the bridge does this on first use) | A new name gets only what an AI tool's first use of a key gets under the care level; registering needs an unlocked vault, is audited (`caller_registered`) and announced in the app ("New AI tool connected"); a registered name or one the owner removed cannot be taken without the owner token | A same-user program can appear as a new AI tool with care-level access; the owner sees it and can remove it |
| T3 fetches localhost broker | Reject requests with `Origin`/`Referer`/`Sec-Fetch-Site`/`Sec-Fetch-Dest`/`Sec-Fetch-User`/`Sec-CH-UA` (not `Sec-Fetch-Mode` alone: Node's `fetch` sends it); strict `Host`; no CORS; management routes need session token | Non-browser local attacker (T4) |
| T4 connects to loopback | Handles are ~190-bit random and stored only as hashes; the session token file is 0600 on Unix (user-profile ACL on Windows); owner-only routes need the in-memory owner token; the CLI and app refuse a `daemon.addr` that is not loopback | A same-user process can use any handle it finds and every route the session token covers; per-process peer-credential checks are not built. Largely game over on desktop OSes; we reduce, not eliminate |
| T4 reads daemon memory | `mlock`, zeroize, short-lived decrypts; keep secrets encrypted in memory under a session key, decrypt per request | Root/debugger can still read; out of scope |
| T8 steals disk | Vault encrypted with Argon2id-derived key; no plaintext ever on disk; SQLite audit log encrypted | Weak password → offline brute force; enforce strength meter and passkey |
| T8 steals unlocked laptop | Auto-lock on idle/sleep/screen lock; approval prompts for sensitive secrets | Short window before lock |
| T6 on upstream | TLS 1.2+ with system roots; certificate verification never disabled; optional pinning per preset | None significant |
| T9 dependency | `cargo deny`, `cargo audit`, vendored lockfile, minimal deps, reproducible builds, Sigstore-signed releases, SBOM published | Zero-day in a trusted crate |
| T10 echoes secrets back | Response scrubbing. The broker strips the caller's `Accept-Encoding`, negotiates gzip/brotli/deflate itself and unpacks before scrubbing; a reply in any other encoding is refused (`undecodable_response`) | Transformed values |
| T8 edits the vault file to restore access | Superseded record versions are erased on every write and a deleted value is purged, so removing the newest row brings nothing back; a log that has had a keyed head reports a missing one as tampering (`audit_tampered`, state `removed`) | Swapping in a complete older copy of the file is not detected: that needs state outside the file |

### Delegation mode (adds to the above)

| Threat | Mitigation | Residual |
|---|---|---|
| T5 dumps memory of *their* machine | Nothing to find: their machine holds only the handle and device key | None |
| T5 tries to reveal via API | Hosted broker exposes no reveal route for grants; error messages never contain upstream auth headers; upstream responses scrubbed | None |
| T5 exceeds policy | Policy enforced on the broker (not client-side); rate/total caps; approvals | Power within policy is by design; owner must scope well (presets help) |
| T5 shares the handle with others | Handle bound to registered device key; requests signed; new device needs owner approval | Dev can proxy their own device for others (accountable via audit) |
| T5 replays requests | Signed requests include timestamp + nonce; 5-minute window; nonce cache | None |
| T7 reads the database | Vault data is ciphertext (zero-knowledge); grants are encrypted to the broker key, which lives in KMS (Phase 3) or an enclave (Phase 4) | Phase 3: operator with KMS access can decrypt grants. **Disclosed in UI** |
| T7 alters audit log | Hash chain + broker signature + copies on both owner and grantee devices | Operator can drop events before signing; mitigated by client-side sequence gaps detection |
| T7 serves malicious web app JS | Desktop app is the trust anchor; web app uses SRI, CSP, signed bundle manifest verified by a small bootstrap; encourage desktop for owners | Classic web E2E weakness; disclosed |
| T6 between grantee and broker | TLS; requests additionally signed with device key (Ed25519) | None |
| A8 broker key theft | KMS-held key never leaves KMS (envelope); Phase 4: key generated inside enclave, non-exportable, attested | Phase 3 operator risk |

## Explicit non-goals and residual risks (say them out loud)

1. **A malicious same-user local process** on a desktop OS can generally defeat any local vault. We reduce exposure; we do not claim immunity.
2. **Env injection** hands plaintext to a process. It exists because some tools need it. It is off by default.
3. **The power problem.** Unseenkey protects the *secret*, and limits the *capability* only as well as the policy is written. Presets and approvals make good policies easy; they do not make bad ones impossible.
4. **Phase 3 hosted broker** requires trusting the operator not to decrypt grants. Phase 4 enclaves remove that trust; until then, clients who cannot accept it should use bring-your-own-broker.
5. **Web app** delivered by our server can be modified by our server. Use the desktop app for the highest assurance.

## Security invariants (must always hold; each has a test)

- INV-1: Plaintext is never written to disk, logs, crash dumps or error messages.
- INV-2: Plaintext leaves the daemon only inside an outgoing request to a host on the secret's upstream list, or via an explicitly audited reveal/injection.
- INV-3: Management routes require the session token. The routes that reveal a value, answer an approval, enroll an unlock method, change settings, name or change a policy, or replace an existing MCP client's token additionally require an owner token, issued only against the password or a device unlock, held in memory and cleared on lock. (Handles themselves are capabilities: any local caller holding one may use it within its policy; the `callers` list restricts MCP identities, not processes.)
- INV-9: A response the scrubber cannot read (an encoding the broker did not ask for) is refused, never passed through.
- INV-10: A write erases the record versions it supersedes; a delete leaves no version of the value in the file.
- INV-4: Every use produces exactly one audit event before the response is returned to the caller.
- INV-5: Policy evaluation defaults to deny; an unknown field or parse error denies.
- INV-6: Local broker rejects any request that carries browser-origin headers.
- INV-7: Sync uploads contain only ciphertext and non-sensitive metadata (names may be encrypted too; see [06](06-cryptography.md)).
- INV-8: Revocation is effective on the next request.

## Disclosure and response

- `SECURITY.md` with a PGP key and a 72-hour first-response commitment.
- Bug bounty from Phase 3 (start with a small private program).
- Incident response runbook in [13](13-operations.md).
