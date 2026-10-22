# unseenkey.com

Static landing page, served by Cloudflare Pages from this directory. No build step.

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
