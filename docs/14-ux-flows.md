# 14 — UX Flows

Design principle: **the secret is shown once, at entry, and never again.** Every screen after that talks about *uses*, *handles*, *policies* and *grants*. If a screen would show a value, the design is wrong.

Second principle: **plain language for owners.** A client with no technical background must understand what they are granting. Every policy is rendered as sentences.

## Onboarding (desktop)

1. **Welcome** → "Create a vault" / "Restore from recovery kit" / "Open existing vault file".
2. **Password** with strength meter (zxcvbn-style, minimum score 3) and the sentence: *"We cannot reset this. Your recovery kit is the only other way in."*
3. **Passkey** (optional, recommended): platform prompt; explanation of what it adds.
4. **Recovery kit**: 24 words displayed once; "I've written them down" checkbox; print/save encrypted PDF option; verification of 3 random words.
5. **First secret**: paste field with auto-detect ("Looks like an OpenAI key"); name pre-filled; upstream shown and locked.
6. **Use it**: three tabs, *Cursor/Claude/Windsurf* (one-click MCP install), *Environment variables* (copy block), *Code* (snippets). The handle appears here; text: *"This is safe to paste anywhere. It only works from this computer and only for OpenAI."*

Target: under 5 minutes to first proxied call.

## Main window

- **Sidebar:** Secrets · Handles · Policies · Approvals (badge) · Activity · Grants (Phase 3) · Settings.
- **Tray/menu-bar icon:** lock state, pending approvals count, quick lock, quick unlock.

### Secrets list
Name, provider icon, type, tags, handle count, last used, status chips (`no upstream` warning, `injection enabled`, `too short to guard`). Search across encrypted metadata (client-side index). Bulk import.

### Secret detail
- Header: name, provider, upstreams (editable, warns when adding wildcards), created/updated, version count.
- **Value: never shown.** A single "Reveal…" button opens a confirmation ("Why do you need it? This will be logged.") and shows the value for 30 s with copy button and a countdown, then clears the clipboard.
- Tabs: Handles · Policies · Activity · Rotation (Phase 4).

### Handle creation dialog
1. Pick policy preset (cards: "Chat only", "Read only", "Payments, no refunds", "Custom…") with the plain-English rendering under each.
2. Who can use it: this computer (default), specific MCP client, any registered device.
3. Expiry: 7 / 30 / 90 days / never (with warning).
4. Result screen: handle string with copy button; per-tool setup snippets; "Handles are safe to share; revoking takes one click."

### Policy editor
- Left: form (allow/deny list with method + path, limits, schedule, approval mode, callers, injection, MCP).
- Right: live plain-English explanation and a "test a request" box (method + path → allow/deny with the matching rule highlighted).
- Validation errors inline; unknown fields impossible in the form (YAML mode for experts with the same validation).

### Approvals
- Desktop notification: *"Cursor wants to POST /v1/transfers using stripe-live. Allow once · Allow always for this path · Deny."* 120 s countdown.
- Approvals page: pending with context (caller, path, policy rule that triggered), history.

### Activity (audit)
- Timeline with filters (secret, caller, kind, status); each row expands to request id, host, path, latency, rule.
- "Verify log" button runs the chain check and shows a green shield or a red warning with the first broken sequence.
- Export signed log (JSON) for a date range.

### `.env` guard
- Banner when a project folder with detected keys is opened via `usk`/desktop: "3 real keys found in `.env`. Move them into the vault and replace with handles?" Diff preview, one click.

## CLI experience

- Hidden input for values; `usk add` confirms detection: `Detected: Stripe live key (sk_live_…). Upstream locked to api.stripe.com. Save as "stripe-live"? [Y/n]`.
- `usk env stripe-live --policy payments` prints copy-ready exports plus one comment line explaining the handle.
- Denials are actionable: `403 policy_denied: POST /v1/refunds is not allowed by policy "payments". Ask the owner: usk request-access stripe-live "need refunds for testing"`.
- Colors and emoji off when not a TTY; `--json` everywhere.

## Delegation flows (Phase 3)

### Owner (Raj) creates a grant — web or desktop
1. Grants → New grant → pick secret(s).
2. Pick preset policy (e.g. *Stripe: payments, no refunds/payouts*) → explanation → optional edits.
3. Expiry (default 30 days), approval rules (default: approvals on money-moving paths), fail mode (default closed).
4. Trust screen: *"The key will be encrypted so only Unseenkey's broker can use it. [Phase 3: operated by Unseenkey. Phase 4: verified enclave, hash …]. Your developer never receives the key."*
5. Invite: email or link; single-use; 24 h.
6. Later: device approval push ("Dev's MacBook wants to use this grant. Approve?").

### Grantee (Dev) accepts
1. Opens link → installs app or uses CLI → `usk grant accept usk_i_…` → registers device (keychain keypair).
2. Waits for owner approval (status shown).
3. Gets handle + setup snippets; local uskd relays signed requests. Everything else feels exactly like self mode.
4. Grantee view: what they can do (explanation), usage, expiry countdown, "request more access", "export my signed log".

### Owner dashboard
- Live feed per grant; charts of calls by endpoint; denials; approvals.
- Buttons: Pause · Extend · Edit policy · Revoke (confirm; immediate).
- Rotation (Phase 4): rotate underlying key without touching the grant.

## Copy guidelines

- Say "use" not "access", "handle" not "token" (tokens sound secret), "grant" not "share".
- Never say "encrypted, so it's safe" without saying what that protects against.
- Error texts always end with the next action.

## Accessibility

- Full keyboard navigation; visible focus; screen-reader labels for chips and buttons; reduced-motion respected; contrast AA; all notifications also appear in-app for users who disable OS notifications.
