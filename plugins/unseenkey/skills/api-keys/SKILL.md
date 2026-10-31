---
name: api-keys
description: Use whenever a task needs an API key, token or other credential, for example calling a provider's API (OpenAI, Anthropic, Stripe, GitHub and others), testing an integration, or working on code or .env files that hold keys. Unseenkey makes the call with the user's key without the key ever reaching you.
---

# Using API keys through Unseenkey

The user keeps their keys in Unseenkey, a vault on their machine. You can use a key; you can never see it. No tool returns a key's value, so do not try to obtain one.

## Calling an API

1. `list_secrets` shows the keys you may use, with each one's provider and the rules that apply to you.
2. `call_api` makes the request. Pass the secret's name, the method, the path or URL, and the body. Unseenkey adds the key on the way out and removes it from the reply.
3. If the call is refused by the rules, use `request_access` and say plainly what you need and why. The user decides. Some actions (deleting things, moving money out, changing keys or billing) ask the user first even when allowed; wait for that answer.
4. `explain_policy` says what a key's rules allow, when you need to know before trying.

## Keys the user has not added yet

Never ask the user to paste a key into the chat, and never write one into a file. Ask them to run this in their own terminal:

```
usk add <name>
```

It asks for the key without showing it and recognises the provider. Then call `list_secrets` again.

## Keys in code and .env files

Do not print, copy or move real keys you find in files. If a project's `.env` holds real keys, suggest `usk guard scan .env` and then `usk guard fix .env`: the keys move into the vault and the file gets handles that only work through Unseenkey.

## When Unseenkey is not ready

If a tool answers that Unseenkey is locked, not set up, or that this AI tool is disconnected, tell the user exactly what the answer says to do (for example: open the Unseenkey app or run `usk unlock`), then try again once they have.
