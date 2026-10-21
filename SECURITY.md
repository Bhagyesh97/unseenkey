# Security Policy

Unseenkey exists to keep secrets out of places they leak. We treat reports about
its own security as the most important input we get.

## Reporting a vulnerability

- Email: security@unseenkey.com (PGP key will be published here before the first public release).
- Or use GitHub's private vulnerability reporting on this repository.
- Please do not open a public issue for anything that could expose a secret.

We commit to a first response within **72 hours** and to keeping you informed
until the issue is resolved. We will credit you in the release notes unless you
prefer otherwise.

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

Published in full at `docs/04-threat-model.md`, including what we do not protect
against. We would rather you read it than trust us.
