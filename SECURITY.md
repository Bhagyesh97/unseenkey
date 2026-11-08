# Security Policy

Unseenkey exists to keep secrets out of places they leak. We treat reports about
its own security as the most important input we get.

## Where your data goes

**Unseenkey has no server in the path. There is no account and no telemetry, and
nothing you store in it or send through it reaches anything we run.** The vault,
the broker and the audit log all live on your machine.

Local does not mean nothing ever leaves your machine. This is what does:

| What | Where it goes | When |
|---|---|---|
| Your API key, inside a request | Only the hosts that key is locked to, over TLS | Every call you or your tools make. This is how a key gets used. |
| A test request with your key | The same provider | When you add or replace a key (`usk add --no-test` skips it) or run `usk secret test` |
| A sign-in request | The provider's own sign-in address | OAuth2 and Google service account keys, when an access token is needed |
| An update check (desktop app only) | GitHub, which sees your IP address and the app's version | At start and every 6 hours. There is no setting to turn this off yet. The `usk` command-line tool never checks. |

To check this yourself: outgoing requests are made in three files,
`crates/daemon/src/proxy.rs`, `keytest.rs` and `oauth.rs`, and the desktop
updater is configured in `apps/desktop/src-tauri/tauri.conf.json`. Everything
else talks to the daemon on 127.0.0.1. A firewall log will show you the same.

**The website is separate.** unseenkey.com is a static page with no analytics,
hosted on Cloudflare, and Unseenkey does not contact it. If you use its
delegation waitlist form, it stores the email, role and note you type, with your
country and browser name, in the maintainer's Cloudflare account.

**What could change this.** Lending a key to someone else through a hosted broker
is designed, not built. A hosted broker has to handle the key while it is in use,
so it would not be local. If it ships, it will be something you opt in to, local
use will keep working without it, and this section will say what it sends before
it ships.

## Status

Alpha. **There has been no external security audit yet.** Unseenkey is built by
one maintainer with AI assistance, as the commit history shows. Use it with keys
you can rotate. The code, the threat model and the release signatures are public
so you can check for yourself.

## Reporting a vulnerability

- Preferred: GitHub's [private vulnerability reporting](https://github.com/Bhagyesh97/unseenkey/security/advisories/new)
  on this repository. The report stays private between you and the maintainer
  until a fix is released and an advisory is published.
- Or email security@unseenkey.com. Do not put working credentials or exploit
  details that expose other people's keys in an email; describe the issue and
  we will move the details to a private advisory.
- Please do not open a public issue for anything that could expose a secret.

We commit to a first response within **72 hours** and to keeping you informed
until the issue is resolved. We will credit you in the release notes unless you
prefer otherwise.

## Supported versions

Security fixes go into the latest release only; please reproduce on it before
reporting. Updating is `scoop update usk`, `brew upgrade usk`, or the desktop
app's built-in updater.

**After updating the command-line tool, run `usk daemon restart`.** The background
service keeps running the old code, with its old bugs, until it restarts. From
0.1.9, `usk` warns you when the running service is a different version, and
`usk doctor` checks it too. Older versions of `usk` do not warn. A restart locks
the vault.

## What it does not protect against

The [threat model](docs/04-threat-model.md) has the full list. The ones that
matter most:

- **A program running as you.** It can use an unlocked vault within your care
  level, add keys, and make care-level handles. It cannot read a key's value or
  approve its own requests through Unseenkey, but on a desktop OS a determined
  program has other ways in. For a hostile agent, also use an OS sandbox.
- **Root, administrator or a debugger** can read the daemon's memory.
- **`usk run`** gives the real value to the program you start, and anything that
  program starts. It is off by default for each key.
- **Whatever a policy allows.** A handle hides the key, not its power. If a policy
  lets a tool delete things, the tool can delete things.
- **Caps count requests, not money.** `--cap 500/day` stops the 501st request. How
  much 500 requests cost depends on the requests.
- **The provider itself.** It gets your key and your request, as it always did.

## Known open issues

Low severity, known and not yet fixed. We add to this list as we find things.

- **Older vault copies.** Swapping in a complete older copy of the vault file is
  not detected. That needs state stored outside the file.
- **A crash leaves no record.** A request that is under way when the service
  crashes, as opposed to a lock, a stop or the caller leaving, has no line in the log.
- **Token files on Windows with a custom vault folder.** Outside your user profile,
  `daemon.token` and the MCP token files get whatever access that folder gives.
- **Preset files can override built-in ones.** A program running as you can put a
  file in the vault's `presets` folder that changes a provider's hosts or rules
  for keys and handles made afterwards. Keys already stored keep their own host lock.
- **Sign-in retries.** A program holding the session token can keep calling the key
  test, which skips the wait after a refused sign-in for a service account key.
- **Your own host is taken on trust.** Unseenkey sends a Supabase or Jira key to the
  host you name and cannot tell whether that project is really yours. `usk import`
  and `usk guard fix` take it from the `SUPABASE_URL` beside the key, so read a
  `.env` you did not write before importing it.
- **Long values in streamed replies.** A multi-line value over 256 bytes, such as a PEM key, is hidden line by line in a streamed reply, because a stream cannot hold back its whole length. Its last short line is not hidden, and neither is base64 of the whole value in a stream. Requests and whole replies are checked for the whole value too.
- **Encodings.** Scrubbing covers the value, base64, percent-encoding and JSON escaping. A program that transforms a value in some other way is not caught.

## Past security fixes

Details are in [CHANGELOG.md](CHANGELOG.md).

| Version | Fixed |
|---|---|
| 0.1.9 | A handle could send the real key to another host; a Supabase or Jira key could go to a stranger's project; a failed key test could show the key; `..` got past policies; some requests went unrecorded; a preset file could send a key to another host during a key test; a host name starting with `127.` could get a key in cleartext; paths could slip past deny rules and approvals |
| 0.1.6 | A program with the session token could take over a connected AI tool's identity |
| 0.1.5 | The session token was enough to reveal keys and approve requests; compressed replies were not scrubbed. From a full review of the code |

## Scope

- The `unseenkey-core` crate, the `usk` CLI, the `uskd` daemon, the desktop app
  and, when they exist, the cloud services and hosted broker.
- Anything that allows plaintext secret material to reach disk, logs, error
  messages, an unauthorised caller, a non-upstream host, or an AI agent's
  context is in scope and treated as critical.

## What we do not consider vulnerabilities

- Attacks requiring root/administrator or a debugger on the user's machine.
- Attacks by a same-user process with arbitrary code execution against the
  local daemon's memory (documented residual risk; see `docs/04-threat-model.md`).
- Misuse of a capability that a policy explicitly allowed.

## Threat model

Published in full at [`docs/04-threat-model.md`](docs/04-threat-model.md), including
what we do not protect against. We would rather you read it than trust us.
