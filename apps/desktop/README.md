# Unseenkey desktop

Tauri 2 + React. The window is a thin view over the local daemon: every
action goes through a Rust command in `src-tauri/src/lib.rs`, which holds the
daemon session token and forwards to the loopback management API. The webview
never speaks HTTP and has no network permission.

What it does (slice 1):

- first run: create the vault, show the 24 recovery words once
- unlock / lock (and auto-lock from the daemon's idle timer)
- secrets: add (provider detected, host-locked), flags, audited reveal, delete
- handles: create with the provider's policy cards and plain-English
  explanation, copy the SDK environment, revoke
- approvals: live prompts (Allow once / Allow always for this rule / Deny) with
  a system notification; the window is brought to the front on a request
- activity: audit log viewer with hash-chain verification
- agents: one-click MCP install for Claude Code, Claude Desktop, Cursor, Windsurf
- `.env` guard: scan and fix a project's `.env`
- tray icon: Open, Lock vault, Quit; closing the window hides it to the tray

The app starts the daemon itself when none is running (it re-executes its own
binary as `daemon run`), so it needs no separate `usk` install. A daemon started
by the CLI is reused, and the CLI reuses one started by the app.

## Build

```
cd apps/desktop
npm install
npm run tauri dev      # hot-reloading UI + debug app
npm run tauri build    # installers under src-tauri/target/release/bundle
```

The crate is excluded from the root Cargo workspace (its own `Cargo.lock`), so
`cargo build --workspace` at the repo root does not pull in Tauri. The icons in
`src-tauri/icons/` are generated with `npx tauri icon app-icon.png`.

Linux needs `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev
librsvg2-dev`; Windows needs the WebView2 runtime (preinstalled on Windows 10
and 11).
