# Provider catalogue (research, 2026-10-30)

Raw material for "paste and done": recognising a pasted key, the hosts it may be sent to, how to attach it, one read-only call to test it, and a safe default rule set. 247 providers, researched from each provider's own documentation by five parallel research passes and merged here; the machine-readable form is [provider-catalogue.json](provider-catalogue.json).

**Status: research, not presets.** Nothing here is used by Unseenkey yet. Entries marked `medium` or `low` confidence, and every key prefix noted as "observed", must be checked against the provider's docs (and ideally a real key) before it becomes a preset. Test calls were chosen to be read-only; a few providers read through POST (Slack `auth.test`, Plaid, Dropbox, GraphQL APIs), which is noted per entry.

What the research changes in the design:

- **Attaching the key is not always enough.** Auth kinds: {'bearer': 122, 'other': 32, 'header': 58, 'basic': 27, 'query': 8}. Signing schemes (AWS SigV4, PayU hashes, Paytm checksums, Pusher HMAC) and token exchanges (PayPal, PhonePe, Zoom, DocuSign, Salesforce, Google service accounts, Auth0, Box, Docker Hub) need broker support beyond a header.
- **Non-standard Authorization schemes are common:** `Bot` (Discord), `Key` (fal, OneSignal), `Token` (Deepgram, Make), `ApiKey` (Novu), `App` (Infobip), `O-Bearer` (PhonePe v2), and a raw key with no scheme (AssemblyAI, Linear, ClickUp, monday.com, SparkPost, PlanetScale `id:token`).
- **The host often depends on the account** (Shopify stores, Supabase projects, Jira sites, Datadog sites, Mailchimp `-usNN` datacenters, Bird `bk_us1_`/`bk_eu1_`, regional EU/US/IN hosts): the paste flow must ask for or infer it, and pin it.
- **"Read only = GET only" is wrong for some APIs:** GraphQL (Linear, monday.com, Shopify, Braintree), POST searches (Algolia, Meilisearch, Square), POST-everything (Plaid, Dropbox, Authorize.Net). Rules there must look at the path or the GraphQL operation.
- **A prefix alone is not proof:** `sk-` (OpenAI, DeepSeek, Moonshot, DashScope, Stability), `AIza` (every Google key), plain UUIDs (Wise, Coinbase Commerce). Shape, variable name and one test call together decide; the test call goes only to the provider those point to, never to several.
- **Some "keys" are public by design** (PostHog `phc_`, Mapbox `pk.`, Segment write keys, GA `G-` ids) and need no protection; some secrets are not HTTP keys at all (database connection strings).
- **Admin keys look like ordinary keys** (OpenAI `sk-admin-`, Anthropic `sk-ant-admin01-`, OpenRouter provisioning keys) and should get the strictest default.
- **New formats:** Cloudflare `cfut_`/`cfat_`/`cfk_`, Supabase `sb_secret_`, Notion `ntn_`, Paddle `pdl_(live|sdbx)_apikey_`. Moved or retired: Coinbase Commerce (shut down), Prisma Accelerate (ends 2026-12-01), Stack Auth (now Hexclave), Xata (relaunched).

- Providers: 247 (already a preset in Unseenkey: 16; new: 231)
- Recognisable key shape: 148; opaque: 99
- With a read-only test call: 212; multi-part credentials: 73; host varies per account: 73
- Confidence: high 95, medium 124, low 28

| Provider | Category | Host | Auth | Key shape | Test call | Env var | Confidence |
|---|---|---|---|---|---|---|---|
| Alibaba Cloud Model Studio (Qwen / DashScope) | ai | dashscope-intl.aliyuncs.com, dashscope.aliyuncs.com, dashscope-us.aliyuncs.com, *.maas.aliyuncs.com (varies) | bearer | `sk-` | `GET /api/v1/models` | `DASHSCOPE_API_KEY` | medium |
| Amazon Bedrock (multi-part) | ai | bedrock-runtime.*.amazonaws.com, bedrock.*.amazonaws.com, bedrock-mantle.*.api.aws (varies) | other | `AKIA`, `ASIA`, `ABSK` | `GET /foundation-models` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | medium |
| Anthropic (Claude API) * | ai | api.anthropic.com | header `x-api-key` | `sk-ant-api03-`, `sk-ant-admin01-` | `GET /v1/models` | `ANTHROPIC_API_KEY` | high |
| AssemblyAI | ai | api.assemblyai.com, api.eu.assemblyai.com, streaming.assemblyai.com, streaming.eu.assemblyai.com, llm-gateway.assemblyai.com | header `Authorization` | opaque | `GET /v2/transcript?limit=1` | `ASSEMBLYAI_API_KEY` | high |
| Azure OpenAI (Microsoft Foundry) (multi-part) | ai | *.openai.azure.com, *.services.ai.azure.com, *.cognitiveservices.azure.com (varies) | header `api-key` | opaque | `GET /openai/v1/models` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` | medium |
| Black Forest Labs (FLUX API) | ai | api.bfl.ai, api.bfl.ml, *.bfl.ai | header `x-key` | opaque | `GET /v1/credits` | `BFL_API_KEY` | medium |
| Cartesia | ai | api.cartesia.ai | bearer | `sk_car_` | `GET /voices` | `CARTESIA_API_KEY` | medium |
| Cerebras Inference | ai | api.cerebras.ai | bearer | `csk-` | `GET /v1/models` | `CEREBRAS_API_KEY` | medium |
| Cohere | ai | api.cohere.com, api.cohere.ai | bearer | opaque | `GET /v1/models` | `CO_API_KEY`, `COHERE_API_KEY` | high |
| Deepgram | ai | api.deepgram.com, api.eu.deepgram.com, agent.deepgram.com | header `Authorization` (Token) | opaque | `GET /v1/projects` | `DEEPGRAM_API_KEY` | medium |
| DeepSeek | ai | api.deepseek.com | bearer | `sk-` | `GET /user/balance` | `DEEPSEEK_API_KEY` | high |
| ElevenLabs | ai | api.elevenlabs.io, api.us.elevenlabs.io, api.eu.residency.elevenlabs.io, api.in.residency.elevenlabs.io | header `xi-api-key` | `sk_` | `GET /v1/user` | `ELEVENLABS_API_KEY`, `ELEVEN_API_KEY` | high |
| fal.ai | ai | fal.run, queue.fal.run, ws.fal.run, rest.alpha.fal.ai, api.fal.ai | header `Authorization` (Key) | <uuid key id>:<32 hex secret> | none | `FAL_KEY`, `FAL_API_KEY` | medium |
| Fireworks AI | ai | api.fireworks.ai | bearer | `fw_` | `GET /inference/v1/models` | `FIREWORKS_API_KEY` | medium |
| Google Gemini API (AI Studio) | ai | generativelanguage.googleapis.com | header `x-goog-api-key` | `AIza` | `GET /v1beta/models` | `GEMINI_API_KEY`, `GOOGLE_API_KEY` | high |
| Google Vertex AI (multi-part) | ai | aiplatform.googleapis.com, *-aiplatform.googleapis.com, oauth2.googleapis.com (varies) | other | Service-account JSON file with type=service_account, project_id, private_key_id, private_key (PEM), client_email; or an AIza... API key in express mode | none | `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT` | medium |
| Groq * | ai | api.groq.com | bearer | `gsk_` | `GET /openai/v1/models` | `GROQ_API_KEY` | high |
| Hugging Face (Hub and Inference Providers) | ai | huggingface.co, router.huggingface.co, api-inference.huggingface.co, *.endpoints.huggingface.cloud | bearer | `hf_` | `GET /api/whoami-v2` | `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN` | high |
| Ideogram | ai | api.ideogram.ai | header `Api-Key` | opaque | none | `IDEOGRAM_API_KEY` | medium |
| Jina AI (Embeddings, Reader, Search) | ai | api.jina.ai, r.jina.ai, s.jina.ai, eu.r.jina.ai, eu.s.jina.ai, deepsearch.jina.ai | bearer | `jina_` | none | `JINA_API_KEY` | medium |
| Krutrim Cloud (Ola) | ai | cloud.olakrutrim.com | bearer | opaque | none | `KRUTRIM_CLOUD_API_KEY`, `KRUTRIM_API_KEY` | low |
| Leonardo.Ai | ai | cloud.leonardo.ai | bearer | opaque | `GET /api/rest/v1/me` | `LEONARDO_API_KEY` | medium |
| Luma AI (Dream Machine / Luma Agents) | ai | api.lumalabs.ai, agents.lumalabs.ai | bearer | `luma-api-`, `luma-` | `GET /dream-machine/v1/generations?limit=1` | `LUMA_AGENTS_API_KEY`, `LUMAAI_API_KEY` | low |
| Mistral AI * | ai | api.mistral.ai, codestral.mistral.ai | bearer | opaque | `GET /v1/models` | `MISTRAL_API_KEY`, `CODESTRAL_API_KEY` | high |
| Moonshot AI (Kimi) | ai | api.moonshot.ai, api.moonshot.cn | bearer | `sk-` | `GET /v1/models` | `MOONSHOT_API_KEY`, `KIMI_API_KEY` | medium |
| NVIDIA NIM (build.nvidia.com API) | ai | integrate.api.nvidia.com, ai.api.nvidia.com | bearer | `nvapi-` | `GET /v1/models` | `NVIDIA_API_KEY`, `NGC_API_KEY` | medium |
| OpenAI * | ai | api.openai.com | bearer | `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-` | `GET /v1/models` | `OPENAI_API_KEY`, `OPENAI_ORG_ID` | high |
| OpenRouter * | ai | openrouter.ai | bearer | `sk-or-v1-` | `GET /api/v1/key` | `OPENROUTER_API_KEY` | high |
| Perplexity API | ai | api.perplexity.ai | bearer | `pplx-` | none | `PERPLEXITY_API_KEY`, `PPLX_API_KEY` | medium |
| Replicate | ai | api.replicate.com | bearer | `r8_` | `GET /v1/account` | `REPLICATE_API_TOKEN`, `REPLICATE_API_KEY` | high |
| Runway | ai | api.dev.runwayml.com | bearer | `key_` | `GET /v1/organization` | `RUNWAYML_API_SECRET` | medium |
| SambaNova Cloud | ai | api.sambanova.ai | bearer | opaque | `GET /v1/models` | `SAMBANOVA_API_KEY` | low |
| Sarvam AI | ai | api.sarvam.ai | header `api-subscription-key` | opaque | none | `SARVAM_API_KEY` | medium |
| Stability AI | ai | api.stability.ai | bearer | `sk-` | `GET /v1/user/account` | `STABILITY_API_KEY` | medium |
| Together AI | ai | api.together.xyz, api.together.ai | bearer | `tgp_v1_` | `GET /v1/models` | `TOGETHER_API_KEY` | medium |
| Vercel AI Gateway | ai | ai-gateway.vercel.sh | bearer | opaque | `GET /v1/credits` | `AI_GATEWAY_API_KEY`, `VERCEL_OIDC_TOKEN` | medium |
| Voyage AI | ai | api.voyageai.com | bearer | `pa-` | none | `VOYAGE_API_KEY` | medium |
| xAI (Grok) | ai | api.x.ai | bearer | `xai-` | `GET /v1/api-key` | `XAI_API_KEY` | medium |
| Z.ai / Zhipu AI (GLM) | ai | api.z.ai, open.bigmodel.cn | bearer | <32 hex>.<16 letters and digits> | none | `ZAI_API_KEY`, `ZHIPUAI_API_KEY` | medium |
| Amplitude (multi-part) | analytics | amplitude.com, analytics.eu.amplitude.com, api2.amplitude.com, api.eu.amplitude.com (varies) | basic | opaque | `GET /api/2/events/list` | `AMPLITUDE_API_KEY`, `AMPLITUDE_SECRET_KEY` | high |
| Google Analytics 4 (multi-part) | analytics | analyticsdata.googleapis.com, analyticsadmin.googleapis.com, www.google-analytics.com, region1.google-analytics.com | other | `G-` | `GET /v1beta/accountSummaries` | `GA_MEASUREMENT_ID`, `NEXT_PUBLIC_GA_MEASUREMENT_ID` | medium |
| Mixpanel (multi-part) | analytics | mixpanel.com, eu.mixpanel.com, in.mixpanel.com, data.mixpanel.com, data-eu.mixpanel.com, api.mixpanel.com, api-eu.mixpanel.com (varies) | basic | opaque | `GET /api/app/me` | `MIXPANEL_SERVICE_ACCOUNT_USERNAME`, `MIXPANEL_SERVICE_ACCOUNT_SECRET` | medium |
| Plausible Analytics | analytics | plausible.io (varies) | bearer | opaque | `GET /api/v1/sites` | `PLAUSIBLE_API_KEY`, `PLAUSIBLE_SITE_ID` | medium |
| PostHog | analytics | us.posthog.com, eu.posthog.com, us.i.posthog.com, eu.i.posthog.com (varies) | bearer | `phx_`, `phc_` | `GET /api/users/@me/` | `POSTHOG_PERSONAL_API_KEY`, `POSTHOG_API_KEY` | medium |
| Segment (Twilio) | analytics | api.segmentapis.com, eu1.api.segmentapis.com, api.segment.io, events.eu1.segmentapis.com (varies) | bearer | `sgp_` | `GET /` | `SEGMENT_WRITE_KEY`, `SEGMENT_PUBLIC_API_TOKEN` | medium |
| Auth0 (Okta) (multi-part) | auth | *.auth0.com (varies) | other | opaque | none | `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID` | medium |
| Clerk | auth | api.clerk.com | bearer | `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_` | `GET /v1/jwks` | `CLERK_SECRET_KEY`, `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | high |
| Kinde (multi-part) | auth | *.kinde.com (varies) | other | opaque | none | `KINDE_CLIENT_ID`, `KINDE_CLIENT_SECRET` | medium |
| Stack Auth (now Hexclave) (multi-part) | auth | api.hexclave.com, api.stack-auth.com | header `X-Stack-Secret-Server-Key` | `ssk_`, `pck_` | `GET /api/v1/users?limit=1` | `STACK_SECRET_SERVER_KEY`, `NEXT_PUBLIC_STACK_PROJECT_ID` | low |
| WorkOS | auth | api.workos.com | bearer | `sk_test_`, `sk_live_`, `sk_` | `GET /organizations?limit=1` | `WORKOS_API_KEY`, `WORKOS_CLIENT_ID` | medium |
| Appwrite (multi-part) | backend | cloud.appwrite.io, *.cloud.appwrite.io (varies) | header `X-Appwrite-Key` | `standard_` | `GET /v1/health` | `APPWRITE_API_KEY`, `APPWRITE_PROJECT_ID` | medium |
| Contentful (multi-part) | backend | cdn.contentful.com, preview.contentful.com, api.contentful.com, upload.contentful.com, graphql.contentful.com, cdn.eu.contentful.com, api.eu.contentful.com (varies) | bearer | `CFPAT-` | `GET /spaces/<space_id>` | `CONTENTFUL_SPACE_ID`, `CONTENTFUL_ACCESS_TOKEN` | high |
| Convex | backend | api.convex.dev, *.convex.cloud, *.convex.site (varies) | bearer | `prod:`, `dev:`, `preview:`, `project:` | `GET /v1/token_details` | `CONVEX_DEPLOY_KEY`, `CONVEX_URL` | medium |
| Firebase (multi-part) | backend | firestore.googleapis.com, identitytoolkit.googleapis.com, securetoken.googleapis.com, firebasestorage.googleapis.com, fcm.googleapis.com, *.firebaseio.com, *.firebasedatabase.app (varies) | other | `AIza` | none | `FIREBASE_SERVICE_ACCOUNT`, `GOOGLE_APPLICATION_CREDENTIALS` | medium |
| PocketBase (self-hosted) (multi-part) | backend |  (varies) | header `Authorization` | `eyJ` | none | `POCKETBASE_URL`, `PB_URL` | low |
| Sanity (multi-part) | backend | *.api.sanity.io, *.apicdn.sanity.io, api.sanity.io (varies) | bearer | `sk` | `GET /v2021-06-07/users/me` | `SANITY_API_TOKEN`, `SANITY_API_READ_TOKEN` | medium |
| Storyblok | backend | api.storyblok.com, api-us.storyblok.com, api-ca.storyblok.com, api-ap.storyblok.com, mapi.storyblok.com, app.storyblokchina.cn (varies) | query | opaque | `GET /v2/cdn/spaces/me?token=<token>` | `STORYBLOK_API_TOKEN`, `STORYBLOK_ACCESS_TOKEN` | medium |
| Strapi (Cloud or self-hosted) (multi-part) | backend | *.strapiapp.com (varies) | bearer | opaque | none | `STRAPI_API_TOKEN`, `STRAPI_URL` | low |
| Supabase (Management API) | backend | api.supabase.com | bearer | `sbp_` | `GET /v1/projects` | `SUPABASE_ACCESS_TOKEN` | high |
| BigCommerce | commerce | api.bigcommerce.com | header `X-Auth-Token` | opaque | `GET /stores/<store_hash>/v2/store` | `BIGCOMMERCE_ACCESS_TOKEN`, `BIGCOMMERCE_STORE_HASH` | medium |
| Shopify Admin API | commerce | *.myshopify.com (varies) | header `X-Shopify-Access-Token` | `shpat_`, `shpca_`, `shppa_`, `shpss_` | `GET /admin/api/2025-07/shop.json` | `SHOPIFY_ACCESS_TOKEN`, `SHOPIFY_ADMIN_API_ACCESS_TOKEN` | high |
| Wix REST API | commerce | www.wixapis.com | header `Authorization` | `IST.` | `GET /site-properties/v4/properties` | `WIX_API_KEY`, `WIX_SITE_ID` | low |
| WooCommerce REST API (multi-part) | commerce | * (varies) | basic | `ck_`, `cs_` | `GET /wp-json/wc/v3/system_status` | `WOOCOMMERCE_CONSUMER_KEY`, `WOOCOMMERCE_CONSUMER_SECRET` | high |
| Crisp (multi-part) | crm | api.crisp.chat | basic | opaque | `GET /v1/website/<website_id>` | `CRISP_TOKEN_IDENTIFIER`, `CRISP_TOKEN_KEY` | high |
| Freshdesk (multi-part) | crm | *.freshdesk.com (varies) | basic | opaque | `GET /api/v2/agents/me` | `FRESHDESK_API_KEY`, `FRESHDESK_DOMAIN` | high |
| HubSpot | crm | api.hubapi.com | bearer | `pat-na1-`, `pat-eu1-` | `GET /account-info/v3/details` | `HUBSPOT_ACCESS_TOKEN`, `HUBSPOT_PRIVATE_APP_TOKEN` | high |
| Intercom | crm | api.intercom.io, api.eu.intercom.io, api.au.intercom.io (varies) | bearer | opaque | `GET /me` | `INTERCOM_ACCESS_TOKEN`, `INTERCOM_TOKEN` | high |
| Pipedrive | crm | api.pipedrive.com, *.pipedrive.com | header `x-api-token` | opaque | `GET /api/v1/users/me` | `PIPEDRIVE_API_TOKEN`, `PIPEDRIVE_API_KEY` | medium |
| Salesforce (multi-part) | crm | *.my.salesforce.com, login.salesforce.com, test.salesforce.com (varies) | bearer | `00D` | `GET /services/oauth2/userinfo` | `SALESFORCE_CLIENT_ID`, `SALESFORCE_CLIENT_SECRET` | medium |
| Zendesk (multi-part) | crm | *.zendesk.com (varies) | basic | opaque | `GET /api/v2/users/me.json` | `ZENDESK_API_TOKEN`, `ZENDESK_EMAIL` | high |
| Chroma Cloud | database | api.trychroma.com, europe-west1.gcp.trychroma.com | header `x-chroma-token` | `ck-` | `GET /api/v2/auth/identity` | `CHROMA_API_KEY`, `CHROMA_TENANT` | low |
| MongoDB Atlas (multi-part) | database | cloud.mongodb.com | other | opaque | `GET /api/atlas/v2/orgs` | `MONGODB_ATLAS_PUBLIC_KEY`, `MONGODB_ATLAS_PRIVATE_KEY` | medium |
| Neon | database | console.neon.tech | bearer | `napi_` | `GET /api/v2/users/me` | `NEON_API_KEY`, `DATABASE_URL` | medium |
| Pinecone | database | api.pinecone.io, *.pinecone.io (varies) | header `Api-Key` | `pcsk_` | `GET /indexes` | `PINECONE_API_KEY` | high |
| PlanetScale (multi-part) | database | api.planetscale.com | header `Authorization` | `pscale_tkn_` | `GET /v1/organizations` | `PLANETSCALE_SERVICE_TOKEN_ID`, `PLANETSCALE_SERVICE_TOKEN` | high |
| Prisma (Accelerate / Prisma Postgres) | database | accelerate.prisma-data.net, api.prisma.io | other | `eyJ` | none | `DATABASE_URL`, `DIRECT_DATABASE_URL` | medium |
| Qdrant Cloud (multi-part) | database | *.cloud.qdrant.io (varies) | header `api-key` | opaque | `GET /collections` | `QDRANT_URL`, `QDRANT_API_KEY` | medium |
| Supabase (project API keys) (multi-part) | database | *.supabase.co (varies) | header `apikey` | `sb_secret_`, `sb_publishable_`, `eyJ` | `GET /auth/v1/settings` | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | high |
| Turso | database | api.turso.tech, *.turso.io (varies) | bearer | `eyJ` | `GET /v1/auth/validate` | `TURSO_API_TOKEN`, `TURSO_AUTH_TOKEN` | high |
| Upstash Redis (REST) (multi-part) | database | *.upstash.io (varies) | bearer | opaque | `GET /ping` | `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | high |
| Weaviate Cloud (multi-part) | database | *.weaviate.cloud, *.weaviate.network (varies) | bearer | opaque | `GET /v1/schema` | `WEAVIATE_URL`, `WEAVIATE_API_KEY` | medium |
| Xata | database | api.xata.tech | bearer | opaque | `GET /organizations` | `XATA_API_KEY`, `XATA_BRANCH` | medium |
| Bitbucket Cloud (multi-part) | devtools | api.bitbucket.org | basic | `ATATT`, `ATCTT` | `GET /2.0/user` | `BITBUCKET_API_TOKEN`, `BITBUCKET_EMAIL` | medium |
| CircleCI | devtools | circleci.com | header `Circle-Token` | `CCIPAT_` | `GET /api/v2/me` | `CIRCLECI_TOKEN`, `CIRCLE_TOKEN` | medium |
| Docker Hub (multi-part) | devtools | hub.docker.com | other | `dckr_pat_`, `dckr_oat_` | `POST /v2/users/login` | `DOCKERHUB_TOKEN`, `DOCKERHUB_USERNAME` | medium |
| Expo (EAS) | devtools | api.expo.dev, exp.host | bearer | opaque | none | `EXPO_TOKEN`, `EXPO_ACCESS_TOKEN` | low |
| Figma | devtools | api.figma.com | header `X-Figma-Token` | `figd_` | `GET /v1/me` | `FIGMA_ACCESS_TOKEN`, `FIGMA_TOKEN` | high |
| GitHub * | devtools | api.github.com, uploads.github.com | bearer | `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | `GET /user` | `GITHUB_TOKEN`, `GH_TOKEN` | high |
| GitLab | devtools | gitlab.com (varies) | header `PRIVATE-TOKEN` | `glpat-`, `gldt-`, `glptt-`, `glrt-`, `gloas-` | `GET /api/v4/user` | `GITLAB_TOKEN`, `GITLAB_PRIVATE_TOKEN` | high |
| npm registry | devtools | registry.npmjs.org | bearer | `npm_` | `GET /-/whoami` | `NPM_TOKEN`, `NODE_AUTH_TOKEN` | medium |
| Postman | devtools | api.getpostman.com | header `X-Api-Key` | `PMAK-` | `GET /me` | `POSTMAN_API_KEY` | medium |
| Upstash QStash | devtools | qstash.upstash.io (varies) | bearer | `sig_` | `GET /v2/schedules` | `QSTASH_TOKEN`, `QSTASH_URL` | medium |
| Amazon SES (multi-part) | email | email.*.amazonaws.com (varies) | other | `AKIA`, `ASIA` | `GET /v2/email/account` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | high |
| beehiiv | email | api.beehiiv.com | bearer | opaque | `GET /v2/publications` | `BEEHIIV_API_KEY`, `BEEHIIV_PUBLICATION_ID` | high |
| Brevo (formerly Sendinblue) | email | api.brevo.com, api.sendinblue.com | header `api-key` | `xkeysib-`, `xsmtpsib-` | `GET /v3/account` | `BREVO_API_KEY`, `SENDINBLUE_API_KEY` | high |
| Customer.io (multi-part) | email | track.customer.io, track-eu.customer.io, api.customer.io, api-eu.customer.io (varies) | basic | opaque | `GET /api/v1/accounts/region` | `CUSTOMERIO_SITE_ID`, `CUSTOMERIO_API_KEY` | medium |
| Kit (formerly ConvertKit) | email | api.kit.com, api.convertkit.com | header `X-Kit-Api-Key` | `kit_` | `GET /v4/account` | `KIT_API_KEY`, `CONVERTKIT_API_KEY` | medium |
| Loops | email | app.loops.so | bearer | opaque | `GET /api/v1/api-key` | `LOOPS_API_KEY` | high |
| Mailchimp Marketing API | email | *.api.mailchimp.com (varies) | basic | <32 hex>-us<1-2 digits> | `GET /3.0/ping` | `MAILCHIMP_API_KEY`, `MAILCHIMP_SERVER_PREFIX` | high |
| Mailchimp Transactional (Mandrill) | email | mandrillapp.com | other | `md-` | `POST /api/1.0/users/ping` | `MANDRILL_API_KEY`, `MAILCHIMP_TRANSACTIONAL_API_KEY` | medium |
| MailerLite | email | connect.mailerlite.com | bearer | `eyJ` | `GET /api/subscribers?limit=1` | `MAILERLITE_API_KEY`, `MAILERLITE_API_TOKEN` | medium |
| MailerSend | email | api.mailersend.com | bearer | `mlsn.` | `GET /v1/api-quota` | `MAILERSEND_API_KEY`, `MAILERSEND_API_TOKEN` | medium |
| Mailgun | email | api.mailgun.net, api.eu.mailgun.net (varies) | basic | `key-` | `GET /v4/domains?limit=1` | `MAILGUN_API_KEY`, `MAILGUN_DOMAIN` | medium |
| Mailtrap | email | send.api.mailtrap.io, bulk.api.mailtrap.io, sandbox.api.mailtrap.io, mailtrap.io | bearer | opaque | `GET /api/accounts` | `MAILTRAP_API_TOKEN`, `MAILTRAP_API_KEY` | low |
| Plunk | email | next-api.useplunk.com, api.useplunk.com (varies) | bearer | `sk_`, `pk_` | none | `PLUNK_API_KEY`, `PLUNK_SECRET_KEY` | low |
| Postmark | email | api.postmarkapp.com | header `X-Postmark-Server-Token` | opaque | `GET /server` | `POSTMARK_SERVER_TOKEN`, `POSTMARK_API_TOKEN` | high |
| Resend * | email | api.resend.com | bearer | `re_` | `GET /domains` | `RESEND_API_KEY` | high |
| SendGrid (Twilio SendGrid) * | email | api.sendgrid.com, api.eu.sendgrid.com (varies) | bearer | `SG.` | `GET /v3/scopes` | `SENDGRID_API_KEY` | high |
| SparkPost (Bird Email) | email | api.sparkpost.com, api.eu.sparkpost.com (varies) | header `Authorization` | opaque | `GET /api/v1/account` | `SPARKPOST_API_KEY` | medium |
| ZeptoMail (Zoho) | email | api.zeptomail.com, api.zeptomail.eu, api.zeptomail.in (varies) | header `Authorization` (Zoho-enczapikey) | opaque | none | `ZEPTOMAIL_TOKEN`, `ZEPTOMAIL_API_KEY` | low |
| Amazon Web Services (AWS) * (multi-part) | hosting | *.amazonaws.com (varies) | other | `AKIA`, `ASIA` | `GET /?Action=GetCallerIdentity&Version=2011-06-15` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | high |
| Bunny.net | hosting | api.bunny.net, storage.bunnycdn.com, *.storage.bunnycdn.com, video.bunnycdn.com (varies) | header `AccessKey` | opaque | `GET /pullzone` | `BUNNY_API_KEY`, `BUNNY_STORAGE_API_KEY` | medium |
| Cloudflare * | hosting | api.cloudflare.com | bearer | `cfut_`, `cfat_`, `cfk_` | `GET /client/v4/user/tokens/verify` | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | high |
| Deno Deploy | hosting | api.deno.com | bearer | `ddp_`, `ddo_` | `GET /v1/organizations/<org_id>/projects` | `DENO_DEPLOY_TOKEN` | low |
| DigitalOcean | hosting | api.digitalocean.com | bearer | `dop_v1_`, `doo_v1_`, `dor_v1_` | `GET /v2/account` | `DIGITALOCEAN_TOKEN`, `DIGITALOCEAN_ACCESS_TOKEN` | high |
| Fly.io | hosting | api.machines.dev, api.fly.io | bearer | `FlyV1 fm2_`, `fm2_`, `fo1_` | `GET /v1/apps?org_slug=personal` | `FLY_API_TOKEN`, `FLY_ACCESS_TOKEN` | medium |
| Framer (Server API) (multi-part) | hosting |  | other | opaque | none | `FRAMER_API_KEY`, `FRAMER_PROJECT_URL` | low |
| GoDaddy | hosting | api.godaddy.com, api.ote-godaddy.com | bearer | opaque | `GET /v1/domains?limit=1` | `GODADDY_PAT`, `GODADDY_API_KEY` | medium |
| Google Cloud (multi-part) | hosting | *.googleapis.com (varies) | other | `AIza` | none | `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT` | medium |
| Heroku | hosting | api.heroku.com | bearer | `HRKU-` | `GET /account` | `HEROKU_API_KEY` | high |
| Hetzner Cloud | hosting | api.hetzner.cloud, api.hetzner.com | bearer | opaque | `GET /v1/servers?per_page=1` | `HCLOUD_TOKEN`, `HETZNER_API_TOKEN` | medium |
| Hostinger * | hosting | developers.hostinger.com | bearer | opaque | `GET /api/hosting/v1/websites` | `HOSTINGER_API_TOKEN`, `API_TOKEN` | medium |
| Koyeb | hosting | app.koyeb.com | bearer | opaque | `GET /v1/account/profile` | `KOYEB_TOKEN` | low |
| Linode (Akamai Cloud) | hosting | api.linode.com | bearer | opaque | `GET /v4/profile` | `LINODE_TOKEN`, `LINODE_CLI_TOKEN` | high |
| Microsoft Azure (multi-part) | hosting | management.azure.com, login.microsoftonline.com (varies) | other | opaque | none | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | low |
| Namecheap (multi-part) | hosting | api.namecheap.com, api.sandbox.namecheap.com | query | opaque | `GET /xml.response?Command=namecheap.users.getBalances&ApiUser={api_user}&UserName={api_user}&ClientIp={client_ip}&ApiKey={key}` | `NAMECHEAP_API_KEY`, `NAMECHEAP_API_USER` | medium |
| Netlify | hosting | api.netlify.com | bearer | opaque | `GET /api/v1/user` | `NETLIFY_AUTH_TOKEN`, `NETLIFY_SITE_ID` | high |
| Railway | hosting | backboard.railway.com, backboard.railway.app | bearer | opaque | `POST /graphql/v2` | `RAILWAY_API_TOKEN`, `RAILWAY_TOKEN` | high |
| Render | hosting | api.render.com | bearer | opaque | `GET /v1/owners?limit=1` | `RENDER_API_KEY` | high |
| Vercel * | hosting | api.vercel.com | bearer | opaque | `GET /v2/user` | `VERCEL_TOKEN`, `VERCEL_ORG_ID` | high |
| Vultr | hosting | api.vultr.com | bearer | opaque | `GET /v2/account` | `VULTR_API_KEY` | medium |
| Webflow | hosting | api.webflow.com | bearer | opaque | `GET /v2/token/introspect` | `WEBFLOW_API_TOKEN`, `WEBFLOW_SITE_API_TOKEN` | medium |
| Google Maps Platform | maps | maps.googleapis.com, places.googleapis.com, routes.googleapis.com, addressvalidation.googleapis.com, roads.googleapis.com, tile.googleapis.com | query | `AIza` | none | `GOOGLE_MAPS_API_KEY`, `NEXT_PUBLIC_GOOGLE_MAPS_API_KEY` | high |
| Mapbox | maps | api.mapbox.com, events.mapbox.com | query | `pk.`, `sk.`, `tk.` | `GET /tokens/v2?access_token=<token>` | `MAPBOX_ACCESS_TOKEN`, `NEXT_PUBLIC_MAPBOX_TOKEN` | high |
| Cloudinary (multi-part) | media | api.cloudinary.com | basic | `cloudinary://` | `GET /v1_1/<cloud_name>/ping` | `CLOUDINARY_URL`, `CLOUDINARY_CLOUD_NAME` | medium |
| ImageKit | media | api.imagekit.io, upload.imagekit.io | basic | `private_`, `public_` | `GET /v1/files?limit=1` | `IMAGEKIT_PRIVATE_KEY`, `IMAGEKIT_PUBLIC_KEY` | medium |
| Ably | messaging | main.realtime.ably.net, rest.ably.io | basic | <appId>.<keyId>:<secret> | `GET /stats?limit=1` | `ABLY_API_KEY`, `ABLY_KEY` | high |
| Bird (new MessageBird platform) | messaging | us1.platform.bird.com, eu1.platform.bird.com (varies) | bearer | `bk_us1_`, `bk_eu1_` | none | `BIRD_API_KEY`, `BIRD_WORKSPACE_ID` | medium |
| Discord (bot token) | messaging | discord.com, discordapp.com | header `Authorization` (Bot) | <base64 user id>.<6 chars>.<27-38 chars> | `GET /api/v10/users/@me` | `DISCORD_TOKEN`, `DISCORD_BOT_TOKEN` | high |
| Exotel (multi-part) | messaging | api.exotel.com, api.in.exotel.com (varies) | basic | opaque | `GET /v1/Accounts/{account_sid}/Calls.json` | `EXOTEL_API_KEY`, `EXOTEL_API_TOKEN` | medium |
| Expo Push Notifications | messaging | exp.host | bearer | opaque | none | `EXPO_ACCESS_TOKEN`, `EXPO_TOKEN` | medium |
| Fast2SMS | messaging | www.fast2sms.com | header `authorization` | opaque | none | `FAST2SMS_API_KEY` | low |
| Firebase Cloud Messaging (FCM HTTP v1) (multi-part) | messaging | fcm.googleapis.com, oauth2.googleapis.com | other | Service-account JSON with type, project_id, private_key (-----BEGIN PRIVATE KEY-----), client_email | none | `GOOGLE_APPLICATION_CREDENTIALS`, `FIREBASE_SERVICE_ACCOUNT_KEY` | medium |
| Gupshup | messaging | api.gupshup.io | header `apikey` | opaque | none | `GUPSHUP_API_KEY`, `GUPSHUP_APP_NAME` | low |
| Infobip (multi-part) | messaging | *.api.infobip.com (varies) | header `Authorization` (App) | opaque | `GET /account/1/balance` | `INFOBIP_API_KEY`, `INFOBIP_BASE_URL` | medium |
| Knock | messaging | api.knock.app | bearer | `sk_`, `sk_test_`, `pk_`, `pk_test_` | `GET /v1/users?page_size=1` | `KNOCK_API_KEY`, `KNOCK_SECRET_API_KEY` | medium |
| MessageBird (legacy REST API) | messaging | rest.messagebird.com, conversations.messagebird.com | header `Authorization` (AccessKey) | `test_` | `GET /balance` | `MESSAGEBIRD_API_KEY`, `MESSAGEBIRD_ACCESS_KEY` | medium |
| MSG91 | messaging | control.msg91.com, api.msg91.com | header `authkey` | opaque | none | `MSG91_AUTH_KEY`, `MSG91_AUTHKEY` | low |
| Novu | messaging | api.novu.co, eu.api.novu.co (varies) | header `Authorization` (ApiKey) | opaque | `GET /v1/environments` | `NOVU_SECRET_KEY`, `NOVU_API_KEY` | medium |
| OneSignal (multi-part) | messaging | api.onesignal.com, onesignal.com | header `Authorization` (Key) | `os_v2_app_`, `os_v2_org_` | `GET /templates?app_id={app_id}&limit=1` | `ONESIGNAL_REST_API_KEY`, `ONESIGNAL_APP_ID` | high |
| Plivo (multi-part) | messaging | api.plivo.com | basic | `MA`, `SA` | `GET /v1/Account/{auth_id}/` | `PLIVO_AUTH_ID`, `PLIVO_AUTH_TOKEN` | high |
| Pusher Channels (multi-part) | messaging | api-*.pusher.com, api.pusherapp.com (varies) | other | opaque | `GET /apps/{app_id}/channels` | `PUSHER_APP_ID`, `PUSHER_KEY` | high |
| Retell AI (voice agents) | messaging | api.retellai.com | bearer | `key_` | `POST /v2/list-agents` | `RETELL_API_KEY` | medium |
| Sinch SMS (multi-part) | messaging | us.sms.api.sinch.com, eu.sms.api.sinch.com, au.sms.api.sinch.com, br.sms.api.sinch.com, ca.sms.api.sinch.com (varies) | bearer | opaque | `GET /xms/v1/{service_plan_id}/batches?page_size=1` | `SINCH_SERVICE_PLAN_ID`, `SINCH_API_TOKEN` | medium |
| Slack * | messaging | slack.com, hooks.slack.com, files.slack.com | bearer | `xoxb-`, `xoxp-`, `xapp-`, `xoxe.xoxp-`, `xoxe-` | `POST /api/auth.test` | `SLACK_BOT_TOKEN`, `SLACK_USER_TOKEN` | high |
| Stream (GetStream) (multi-part) | messaging | chat.stream-io-api.com, video.stream-io-api.com, feeds.stream-io-api.com | other | opaque | `GET /app?api_key={api_key}` | `STREAM_API_KEY`, `STREAM_API_SECRET` | low |
| Telegram Bot API | messaging | api.telegram.org | other | <bot id digits>:<35 letters, digits, - or _> | `GET /bot{token}/getMe` | `TELEGRAM_BOT_TOKEN`, `BOT_TOKEN` | high |
| Telnyx | messaging | api.telnyx.com | bearer | `KEY` | `GET /v2/balance` | `TELNYX_API_KEY` | high |
| Twilio * (multi-part) | messaging | api.twilio.com, messaging.twilio.com, verify.twilio.com, lookups.twilio.com, conversations.twilio.com, voice.twilio.com, video.twilio.com, api.dublin.ie1.twilio.com, api.sydney.au1.twilio.com | basic | `AC`, `SK` | `GET /2010-04-01/Accounts/{AccountSid}.json` | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` | high |
| Vapi (voice AI agents) | messaging | api.vapi.ai | bearer | opaque | `GET /assistant?limit=1` | `VAPI_API_KEY`, `VAPI_PRIVATE_KEY` | high |
| Vonage (Nexmo) (multi-part) | messaging | rest.nexmo.com, api.nexmo.com, api-eu.vonage.com, api-us.vonage.com | basic | opaque | `GET /account/get-balance` | `VONAGE_API_KEY`, `VONAGE_API_SECRET` | medium |
| WhatsApp Cloud API (Meta) | messaging | graph.facebook.com | bearer | `EAA` | `GET /me` | `WHATSAPP_TOKEN`, `WHATSAPP_ACCESS_TOKEN` | medium |
| Better Stack (Uptime) | monitoring | uptime.betterstack.com, telemetry.betterstack.com | bearer | opaque | `GET /api/v2/monitors` | `BETTERSTACK_API_TOKEN`, `BETTERUPTIME_API_TOKEN` | medium |
| Datadog (multi-part) | monitoring | api.datadoghq.com, api.us3.datadoghq.com, api.us5.datadoghq.com, api.datadoghq.eu, api.ap1.datadoghq.com, api.ap2.datadoghq.com, api.ddog-gov.com (varies) | header `DD-API-KEY` | opaque | `GET /api/v1/validate` | `DD_API_KEY`, `DD_APP_KEY` | high |
| Grafana Cloud | monitoring | grafana.com, www.grafana.com, *.grafana.net (varies) | bearer | `glc_`, `glsa_` | `GET /api/stack-regions` | `GRAFANA_CLOUD_ACCESS_POLICY_TOKEN`, `GRAFANA_AUTH` | medium |
| Honeycomb | monitoring | api.honeycomb.io, api.eu1.honeycomb.io (varies) | header `X-Honeycomb-Team` | `hcaik_`, `hcxik_`, `hcxmk_` | `GET /1/auth` | `HONEYCOMB_API_KEY`, `OTEL_EXPORTER_OTLP_HEADERS` | medium |
| Langfuse (multi-part) | monitoring | cloud.langfuse.com, us.cloud.langfuse.com, jp.cloud.langfuse.com, hipaa.cloud.langfuse.com (varies) | basic | `pk-lf-`, `sk-lf-` | `GET /api/public/projects` | `LANGFUSE_SECRET_KEY`, `LANGFUSE_PUBLIC_KEY` | high |
| LangSmith | monitoring | api.smith.langchain.com, eu.api.smith.langchain.com, apac.api.smith.langchain.com, aws.api.smith.langchain.com | header `x-api-key` | `lsv2_pt_`, `lsv2_sk_`, `lsv2_tr_` | `GET /api/v1/sessions?limit=1` | `LANGSMITH_API_KEY`, `LANGCHAIN_API_KEY` | medium |
| LogRocket | monitoring | api.logrocket.com | bearer (token) | opaque | `GET /v1/orgs/<org-id>/apps/<project-id>/audit/logs/?limit=1` | `LOGROCKET_API_KEY`, `LOGROCKET_APP_ID` | low |
| New Relic | monitoring | api.newrelic.com, api.eu.newrelic.com (varies) | header `API-Key` | `NRAK-` | `POST /graphql` | `NEW_RELIC_API_KEY`, `NEW_RELIC_LICENSE_KEY` | high |
| Sentry | monitoring | sentry.io, us.sentry.io, de.sentry.io (varies) | bearer | `sntryu_`, `sntrys_` | `GET /api/0/organizations/` | `SENTRY_AUTH_TOKEN`, `SENTRY_ORG` | high |
| Alpha Vantage | other | www.alphavantage.co | query | opaque | `GET /query?function=GLOBAL_QUOTE&symbol=IBM` | `ALPHA_VANTAGE_API_KEY`, `ALPHAVANTAGE_API_KEY` | high |
| Docusign (multi-part) | other | account.docusign.com, account-d.docusign.com, *.docusign.net (varies) | other | `-----BEGIN RSA PRIVATE KEY-----` | `GET /oauth/userinfo` | `DOCUSIGN_INTEGRATION_KEY`, `DOCUSIGN_USER_ID` | medium |
| Finnhub | other | finnhub.io | header `X-Finnhub-Token` | opaque | `GET /api/v1/quote?symbol=AAPL` | `FINNHUB_API_KEY`, `FINNHUB_TOKEN` | medium |
| Make (Integromat) | other | hook.eu1.make.com, hook.eu2.make.com, hook.us1.make.com, hook.us2.make.com, eu1.make.com, eu2.make.com, us1.make.com, us2.make.com (varies) | other (Token) | `https://hook.` | `GET /api/v2/users/me` | `MAKE_WEBHOOK_URL`, `MAKE_API_TOKEN` | low |
| Massive (formerly Polygon.io) | other | api.massive.com, api.polygon.io | bearer | opaque | `GET /v3/reference/tickers?limit=1` | `POLYGON_API_KEY`, `MASSIVE_API_KEY` | medium |
| OpenWeatherMap | other | api.openweathermap.org, pro.openweathermap.org | query | opaque | `GET /data/2.5/weather?q=London&appid=<key>` | `OPENWEATHER_API_KEY`, `OPENWEATHERMAP_API_KEY` | high |
| Zapier Webhooks | other | hooks.zapier.com | other | `https://hooks.zapier.com/hooks/catch/` | none | `ZAPIER_WEBHOOK_URL` | medium |
| Adyen | payments | checkout-test.adyen.com, *-checkout-live.adyenpayments.com, management-test.adyen.com, management-live.adyen.com, pal-test.adyen.com, *-pal-live.adyenpayments.com, balanceplatform-api-test.adyen.com, balanceplatform-api-live.adyen.com (varies) | header `X-API-Key` | `AQE` | `GET /v3/me` | `ADYEN_API_KEY`, `ADYEN_MERCHANT_ACCOUNT` | medium |
| Authorize.Net (multi-part) | payments | api.authorize.net, apitest.authorize.net, api2.authorize.net | other | opaque | `POST /xml/v1/request.api` | `AUTHORIZE_NET_API_LOGIN_ID`, `AUTHORIZE_NET_TRANSACTION_KEY` | high |
| Braintree (multi-part) | payments | payments.braintree-api.com, payments.sandbox.braintree-api.com, api.braintreegateway.com, api.sandbox.braintreegateway.com | basic | opaque | `POST /graphql` | `BRAINTREE_MERCHANT_ID`, `BRAINTREE_PUBLIC_KEY` | medium |
| Cashfree Payments (multi-part) | payments | api.cashfree.com, sandbox.cashfree.com, payout-api.cashfree.com, payout-gamma.cashfree.com | header `x-client-id` | opaque | `GET /pg/orders/unseenkey_verify_nonexistent` | `CASHFREE_APP_ID`, `CASHFREE_SECRET_KEY` | medium |
| Chargebee | payments | *.chargebee.com (varies) | basic | `live_`, `test_` | `GET /api/v2/customers?limit=1` | `CHARGEBEE_API_KEY`, `CHARGEBEE_SITE` | medium |
| Checkout.com | payments | api.checkout.com, api.sandbox.checkout.com, *.api.checkout.com, *.api.sandbox.checkout.com, *.access.checkout.com, *.access.sandbox.checkout.com (varies) | bearer | `sk_sbox_`, `sk_` | `GET /payments?reference=unseenkey-verify` | `CHECKOUT_SECRET_KEY`, `CKO_SECRET_KEY` | medium |
| Coinbase Commerce (legacy) | payments | api.commerce.coinbase.com | header `X-CC-Api-Key` | opaque | `GET /charges?limit=1` | `COINBASE_COMMERCE_API_KEY`, `COINBASE_COMMERCE_WEBHOOK_SECRET` | low |
| Coinbase Developer Platform (CDP) (multi-part) | payments | api.cdp.coinbase.com, api.coinbase.com, api.developer.coinbase.com | other | key id: UUID (or legacy organizations/<org>/apiKeys/<id>); key secret: base64 Ed25519 key (or legacy EC PEM '-----BEGIN EC PRIVATE KEY-----') | `GET /platform/v2/evm/accounts` | `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` | medium |
| Creem | payments | api.creem.io, test-api.creem.io | header `x-api-key` | `creem_` | `GET /v1/products/search` | `CREEM_API_KEY`, `CREEM_WEBHOOK_SECRET` | low |
| Dodo Payments | payments | live.dodopayments.com, test.dodopayments.com | bearer | `dodo_live_`, `dodo_test_` | `GET /products?page_size=1` | `DODO_PAYMENTS_API_KEY`, `DODO_PAYMENTS_WEBHOOK_KEY` | medium |
| Flutterwave | payments | api.flutterwave.com, idp.flutterwave.com, developersandbox-api.flutterwave.com, f4bexperience.flutterwave.com | bearer | `FLWSECK-`, `FLWSECK_TEST-` | `GET /v3/balances` | `FLW_SECRET_KEY`, `FLUTTERWAVE_SECRET_KEY` | medium |
| Gumroad | payments | api.gumroad.com | bearer | opaque | `GET /v2/user` | `GUMROAD_ACCESS_TOKEN`, `GUMROAD_API_KEY` | medium |
| Instamojo (multi-part) | payments | api.instamojo.com, test.instamojo.com | other | opaque | `POST /oauth2/token/` | `INSTAMOJO_CLIENT_ID`, `INSTAMOJO_CLIENT_SECRET` | medium |
| Klarna | payments | api.klarna.com, api-na.klarna.com, api-oc.klarna.com, api.playground.klarna.com, api-na.playground.klarna.com, api-oc.playground.klarna.com (varies) | basic | `klarna_live_api_`, `klarna_test_api_` | none | `KLARNA_API_KEY`, `KLARNA_USERNAME` | medium |
| Lemon Squeezy | payments | api.lemonsqueezy.com | bearer | `eyJ` | `GET /v1/users/me` | `LEMONSQUEEZY_API_KEY`, `LEMON_SQUEEZY_API_KEY` | high |
| Mercado Pago | payments | api.mercadopago.com | bearer | `APP_USR-`, `TEST-` | `GET /users/me` | `MERCADOPAGO_ACCESS_TOKEN`, `MP_ACCESS_TOKEN` | high |
| Midtrans | payments | api.midtrans.com, api.sandbox.midtrans.com, app.midtrans.com, app.sandbox.midtrans.com | basic | `SB-Mid-server-`, `Mid-server-` | `GET /v2/unseenkey-verify-nonexistent/status` | `MIDTRANS_SERVER_KEY`, `MIDTRANS_CLIENT_KEY` | medium |
| Mollie | payments | api.mollie.com | bearer | `live_`, `test_`, `access_` | `GET /v2/methods` | `MOLLIE_API_KEY`, `MOLLIE_ACCESS_TOKEN` | high |
| Paddle Billing | payments | api.paddle.com, sandbox-api.paddle.com | bearer | `pdl_live_apikey_`, `pdl_sdbx_apikey_` | `GET /event-types` | `PADDLE_API_KEY`, `PADDLE_ENVIRONMENT` | high |
| PayPal (REST API) (multi-part) | payments | api-m.paypal.com, api-m.sandbox.paypal.com | other | opaque | `POST /v1/oauth2/token` | `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` | high |
| Paystack | payments | api.paystack.co | bearer | `sk_live_`, `sk_test_` | `GET /balance` | `PAYSTACK_SECRET_KEY`, `PAYSTACK_PUBLIC_KEY` | high |
| Paytm Payment Gateway (multi-part) | payments | secure.paytmpayments.com, securestage.paytmpayments.com, securegw.paytm.in, securegw-stage.paytm.in | other | opaque | none | `PAYTM_MID`, `PAYTM_MERCHANT_KEY` | low |
| PayU India (multi-part) | payments | info.payu.in, test.payu.in, secure.payu.in, apitest.payu.in, oneapi.payu.in | other | opaque | none | `PAYU_MERCHANT_KEY`, `PAYU_MERCHANT_SALT` | medium |
| PhonePe Payment Gateway (multi-part) | payments | api.phonepe.com, api-preprod.phonepe.com | other (O-Bearer) | opaque | `POST /apis/identity-manager/v1/oauth/token` | `PHONEPE_CLIENT_ID`, `PHONEPE_CLIENT_SECRET` | medium |
| Plaid (multi-part) | payments | production.plaid.com, sandbox.plaid.com | header `PLAID-SECRET` | opaque | `POST /institutions/get` | `PLAID_CLIENT_ID`, `PLAID_SECRET` | high |
| Polar | payments | api.polar.sh, sandbox-api.polar.sh | bearer | `polar_oat_` | `GET /v1/products/?limit=1` | `POLAR_ACCESS_TOKEN`, `POLAR_OAT` | high |
| Razorpay (multi-part) | payments | api.razorpay.com | basic | `rzp_live_`, `rzp_test_` | `GET /v1/payments?count=1` | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` | high |
| Recurly | payments | v3.recurly.com, v3.eu.recurly.com | basic | opaque | `GET /sites` | `RECURLY_API_KEY`, `RECURLY_SUBDOMAIN` | medium |
| RevenueCat | payments | api.revenuecat.com | bearer | `sk_` | `GET /v2/projects` | `REVENUECAT_SECRET_KEY`, `REVENUECAT_API_KEY` | medium |
| Square | payments | connect.squareup.com, connect.squareupsandbox.com | bearer | `EAAA` | `GET /v2/locations` | `SQUARE_ACCESS_TOKEN`, `SQUARE_APPLICATION_ID` | high |
| Stripe * | payments | api.stripe.com, files.stripe.com, meter-events.stripe.com | bearer | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` | `GET /v1/balance` | `STRIPE_SECRET_KEY`, `STRIPE_API_KEY` | high |
| Wise | payments | api.wise.com, api.transferwise.com, api.wise-sandbox.com, api.sandbox.transferwise.tech | bearer | opaque | `GET /v2/profiles` | `WISE_API_TOKEN`, `WISE_API_KEY` | medium |
| Xendit | payments | api.xendit.co | basic | `xnd_development_`, `xnd_production_` | `GET /balance` | `XENDIT_SECRET_KEY`, `XENDIT_API_KEY` | medium |
| Zerodha Kite Connect (multi-part) | payments | api.kite.trade | header `Authorization` (token) | opaque | `GET /user/profile` | `KITE_API_KEY`, `KITE_API_SECRET` | high |
| Airtable | productivity | api.airtable.com | bearer | `pat` | `GET /v0/meta/whoami` | `AIRTABLE_API_KEY`, `AIRTABLE_ACCESS_TOKEN` | high |
| Asana | productivity | app.asana.com | bearer | `1/`, `2/` | `GET /api/1.0/users/me` | `ASANA_ACCESS_TOKEN`, `ASANA_PAT` | medium |
| Cal.com | productivity | api.cal.com | bearer | `cal_live_`, `cal_` | `GET /v2/me` | `CAL_API_KEY`, `CALCOM_API_KEY` | medium |
| Calendly | productivity | api.calendly.com | bearer | `eyJ` | `GET /users/me` | `CALENDLY_API_KEY`, `CALENDLY_PERSONAL_ACCESS_TOKEN` | high |
| ClickUp | productivity | api.clickup.com | header `Authorization` | `pk_` | `GET /api/v2/user` | `CLICKUP_API_TOKEN`, `CLICKUP_API_KEY` | high |
| Coda | productivity | coda.io | bearer | opaque | `GET /apis/v1/whoami` | `CODA_API_TOKEN`, `CODA_API_KEY` | high |
| Google Sheets / Drive (multi-part) | productivity | sheets.googleapis.com, www.googleapis.com, oauth2.googleapis.com | other | `AIza`, `ya29.` | `GET /drive/v3/about?fields=user` | `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_SERVICE_ACCOUNT_KEY` | medium |
| Jira / Confluence (Atlassian Cloud) (multi-part) | productivity | *.atlassian.net, api.atlassian.com (varies) | basic | `ATATT` | `GET /rest/api/3/myself` | `JIRA_API_TOKEN`, `JIRA_EMAIL` | high |
| Jotform | productivity | api.jotform.com, eu-api.jotform.com, hipaa-api.jotform.com (varies) | header `APIKEY` | opaque | `GET /user` | `JOTFORM_API_KEY` | medium |
| Linear | productivity | api.linear.app | header `Authorization` | `lin_api_`, `lin_oauth_` | `POST /graphql` | `LINEAR_API_KEY`, `LINEAR_ACCESS_TOKEN` | high |
| Miro | productivity | api.miro.com | bearer | `eyJ` | `GET /v1/oauth-token` | `MIRO_ACCESS_TOKEN`, `MIRO_TOKEN` | low |
| monday.com | productivity | api.monday.com | header `Authorization` | `eyJ` | `POST /v2` | `MONDAY_API_TOKEN`, `MONDAY_API_KEY` | high |
| Notion * | productivity | api.notion.com | bearer | `ntn_`, `secret_` | `GET /v1/users/me` | `NOTION_API_KEY`, `NOTION_TOKEN` | high |
| Tally | productivity | api.tally.so | bearer | opaque | `GET /users/me` | `TALLY_API_KEY` | high |
| Todoist | productivity | api.todoist.com | bearer | opaque | `GET /api/v1/projects?limit=1` | `TODOIST_API_TOKEN`, `TODOIST_API_KEY` | medium |
| Trello (multi-part) | productivity | api.trello.com | query | `ATTA` | `GET /1/members/me` | `TRELLO_API_KEY`, `TRELLO_TOKEN` | high |
| Typeform | productivity | api.typeform.com, api.eu.typeform.com (varies) | bearer | `tfp_` | `GET /me` | `TYPEFORM_API_TOKEN`, `TYPEFORM_TOKEN` | medium |
| Zoom (multi-part) | productivity | api.zoom.us, zoom.us | other | opaque | `GET /v2/users/me` | `ZOOM_ACCOUNT_ID`, `ZOOM_CLIENT_ID` | high |
| Algolia (multi-part) | search | *.algolia.net, *.algolianet.com, analytics.algolia.com, analytics.de.algolia.com, insights.algolia.io (varies) | header `X-Algolia-API-Key` | opaque | `GET /1/indexes?page=0&hitsPerPage=1` | `ALGOLIA_APP_ID`, `ALGOLIA_ADMIN_API_KEY` | medium |
| Meilisearch Cloud (multi-part) | search | *.meilisearch.io (varies) | bearer | opaque | `GET /version` | `MEILISEARCH_HOST`, `MEILISEARCH_API_KEY` | medium |
| Typesense Cloud (multi-part) | search | *.a1.typesense.net, cloud.typesense.org (varies) | header `X-TYPESENSE-API-KEY` | opaque | `GET /collections` | `TYPESENSE_API_KEY`, `TYPESENSE_HOST` | medium |
| LinkedIn API | social | api.linkedin.com, www.linkedin.com | bearer | `AQ` | `GET /v2/userinfo` | `LINKEDIN_ACCESS_TOKEN`, `LINKEDIN_CLIENT_ID` | high |
| Meta Graph API (Facebook / Instagram) | social | graph.facebook.com, graph.instagram.com, rupload.facebook.com, graph-video.facebook.com | bearer | `EAA`, `IGAA`, `IG` | `GET /me?fields=id,name` | `FACEBOOK_ACCESS_TOKEN`, `META_ACCESS_TOKEN` | medium |
| Pinterest API v5 | social | api.pinterest.com, api-sandbox.pinterest.com | bearer | `pina_` | `GET /v5/user_account` | `PINTEREST_ACCESS_TOKEN`, `PINTEREST_APP_ID` | medium |
| Reddit API (multi-part) | social | oauth.reddit.com, www.reddit.com | bearer | opaque | `GET /api/v1/me` | `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET` | medium |
| Threads API (Meta) | social | graph.threads.net | bearer | `TH` | `GET /v1.0/me?fields=id,username` | `THREADS_ACCESS_TOKEN`, `THREADS_USER_ID` | medium |
| TikTok API (Login Kit / Content Posting) | social | open.tiktokapis.com | bearer | `act.` | `GET /v2/user/info/?fields=open_id,display_name` | `TIKTOK_ACCESS_TOKEN`, `TIKTOK_CLIENT_KEY` | medium |
| X (Twitter) API v2 | social | api.x.com, api.twitter.com, upload.twitter.com | bearer | `AAAAAAAAAAAAAAAAAAAAA` | `GET /2/usage/tweets` | `X_BEARER_TOKEN`, `TWITTER_BEARER_TOKEN` | medium |
| YouTube Data API v3 | social | www.googleapis.com, youtube.googleapis.com | query | `AIza` | `GET /youtube/v3/i18nLanguages?part=snippet` | `YOUTUBE_API_KEY`, `GOOGLE_API_KEY` | high |
| Backblaze B2 (multi-part) | storage | api.backblazeb2.com, *.backblazeb2.com (varies) | basic | `K00` | `GET /b2api/v4/b2_authorize_account` | `B2_APPLICATION_KEY_ID`, `B2_APPLICATION_KEY` | high |
| Box (multi-part) | storage | api.box.com, upload.box.com | bearer | opaque | `GET /2.0/users/me` | `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET` | high |
| Cloudflare R2 (S3 API) (multi-part) | storage | *.r2.cloudflarestorage.com (varies) | other | opaque | none | `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | medium |
| Dropbox (multi-part) | storage | api.dropboxapi.com, content.dropboxapi.com, notify.dropboxapi.com | bearer | `sl.` | `POST /2/users/get_current_account` | `DROPBOX_ACCESS_TOKEN`, `DROPBOX_REFRESH_TOKEN` | high |
| UploadThing | storage | api.uploadthing.com, *.ingest.uploadthing.com (varies) | header `x-uploadthing-api-key` | `sk_live_`, `eyJ` | none | `UPLOADTHING_TOKEN`, `UPLOADTHING_SECRET` | low |
| Vercel Blob | storage | vercel.com, blob.vercel-storage.com, *.public.blob.vercel-storage.com (varies) | bearer | `vercel_blob_rw_` | none | `BLOB_READ_WRITE_TOKEN` | low |

`*` = already a preset.

## Problems found while merging

- amazon-ses: verify host email.<region>.amazonaws.com not in hosts ['email.*.amazonaws.com']
- authorize-net: verify uses POST (must be read-only)
- aws-bedrock: verify host bedrock.<region>.amazonaws.com not in hosts ['bedrock-runtime.*.amazonaws.com', 'bedrock.*.amazonaws.com', 'bedrock-mantle.*.api.aws']
- braintree: verify uses POST (must be read-only)
- docker-hub: verify uses POST (must be read-only)
- dropbox: verify uses POST (must be read-only)
- framer: no hosts
- instamojo: verify uses POST (must be read-only)
- linear: verify uses POST (must be read-only)
- mailchimp-transactional: verify uses POST (must be read-only)
- monday: verify uses POST (must be read-only)
- new-relic: verify uses POST (must be read-only)
- paypal: verify uses POST (must be read-only)
- phonepe: verify uses POST (must be read-only)
- plaid: verify uses POST (must be read-only)
- pocketbase: no hosts
- pusher-channels: verify host api-<cluster>.pusher.com not in hosts ['api-*.pusher.com', 'api.pusherapp.com']
- qdrant-cloud: verify host <cluster>.<region>.<cloud>.cloud.qdrant.io:6333 not in hosts ['*.cloud.qdrant.io']
- railway: verify uses POST (must be read-only)
- retell-ai: verify uses POST (must be read-only)
- slack: verify uses POST (must be read-only)
- woocommerce: verify host <store domain> not in hosts ['*']
