# CloudGram

CloudGram is an original, text-first messenger built for Cloudflare Pages + Pages Functions + D1. It intentionally has no uploads, R2 bucket, file inputs, photo messages, voice notes, or GIF storage. Avatars are generated from deterministic seeds.

## Architecture

- **Frontend:** React + TypeScript + Vite, Framer Motion, Lucide icons, responsive CSS.
- **Backend:** Cloudflare Pages Functions in `functions/api/[[path]].ts`.
- **Database:** Cloudflare D1 with migrations in `database/migrations`.
- **Auth:** server-checked sessions, PBKDF2 password hashing with Web Crypto, HttpOnly cookie.
- **Realtime:** optimistic sends plus a lightweight `/api/events` Server-Sent Events channel. Typing is transient and is never stored in D1. A Durable Object can be added later for multi-isolate fanout without changing the API.
- **AI/MCP:** Cloud AI is a real provider boundary. With no provider configured it clearly reports “AI provider не настроен”; it never returns fake model output. The safe tool boundary is documented in `functions/ai-tools.ts`.

## Local development

```bash
npm install
npm run dev
```

For local D1 with Wrangler:

```bash
npx wrangler d1 migrations apply socialcf-db --local
npx wrangler pages dev dist --d1=DB=socialcf-db
```

## Cloudflare setup

1. Create or select a D1 database and set its ID in `wrangler.toml`.
2. Apply migrations: `npx wrangler d1 migrations apply socialcf-db --remote`.
3. Connect the repository to Cloudflare Pages with build command `npm run build`, output directory `dist`, production branch `main`.
4. Add the D1 binding named `DB` to both preview and production. No R2 or paid service is required.
5. Optional AI provider values belong in Cloudflare secrets/environment variables only; do not commit them.

The Pages project is designed to deploy automatically from GitHub `main`. The free `*.pages.dev` hostname is used; no paid domain is required.

## Security notes

All authorization is enforced in the Function: message edits/deletes require the sender, admin changes require the group owner/admin, blocked users cannot create or send in direct chats, and IDs are never trusted from the client. Queries are parameterized and paginated. Rate limits are bounded in-process and should be upgraded to a Durable Object/KV-backed limiter for large production scale.

## Scope

Groups, channels, saved messages, reactions, replies, message search, profile/settings, blocking, reports, emoji picker, drafts and PWA shell are included. File uploads are intentionally not implemented.
