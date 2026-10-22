# unseenkey.com

Static landing page, served by Cloudflare Pages from this directory. Cloudflare runs no build: the two scripts are bundled locally and committed.

```
cd site && npm install && npm run build      # src/app.js + anime.js → public/app.js; src/hero3d.js + three → public/hero3d.js
npm run serve                                # preview at http://127.0.0.1:8766/
```

`public/hero-still.png` (the hero for phones and reduced-motion users) is a capture of the 3D key at rest; `public/presets.json` is generated from `usk --json presets` and `usk --json policy explain` of the shipped CLI. The page uses no third-party hosts at all: scripts are bundled, fonts are the system's, and there is no analytics.

Pages project settings:

| Setting | Value |
|---|---|
| Root directory | `site` |
| Build command | (empty) |
| Build output directory | `public` |
| Custom domains | `unseenkey.com`, `www.unseenkey.com` |
| KV binding | `WAITLIST` → a KV namespace (Workers & Pages → KV → Create), bound under Settings → Bindings |

`public/` is the page and its assets (the diagrams are copies of `docs/assets/`; the icons come from `apps/desktop/app-icon.png`). `functions/api/waitlist.js` is a Pages Function that stores delegation-waitlist signups in the `WAITLIST` namespace; without the binding it answers 503 and the page offers email instead. Read signups with `wrangler kv key list --namespace-id <id>` or in the dashboard.

Every push to `main` that touches `site/` redeploys. Preview deployments come from other branches.
