# Supreme Fantasy League API

Express + MongoDB backend, packaged to deploy on Vercel as a single serverless
function. **`server.js` is completely unchanged** — every route, model, and
piece of business logic is exactly what it was before. Only the files around
it are new, so the API's behaviour, routes, and response shapes (and
therefore the existing frontend's integration with it) are unaffected.

## What was added, and why

| File | Purpose |
|---|---|
| `api/index.js` | The actual Vercel serverless function. Vercel has no long-running `app.listen()` process, so this wrapper (1) awaits `prepareRuntime()` — the DB connection + startup tasks that used to run inside `start()` — before handling a request, and (2) disables Vercel's built-in body parsing so Express's own `express.json()`/`express.urlencoded()` middleware in `server.js` still works. |
| `vercel.json` | Routes every `/api/*` request to that one function, and registers the existing `/api/internal/cron/maintenance` route as a scheduled Vercel Cron job. |
| `package.json` / `package-lock.json` | Dependencies inferred from `server.js`'s `require()` calls. Express is pinned to the 4.x line on purpose — `server.js` uses bare `'*'` wildcard routes (`app.get('*', ...)`, `app.use('/api/*', ...)`) which are **not** valid path patterns in Express 5. |
| `.env.example` | Every environment variable `server.js` reads, with defaults and short explanations. |
| `.gitignore` | Standard Node/Vercel ignores. |

Nothing here touches routing logic, auth, CORS, cookies, or response formats.

## 1. Deploy

1. Push this repo to GitHub (or GitLab/Bitbucket).
2. In Vercel: **Add New → Project**, import the repo. Vercel will
   auto-detect the Node.js runtime from `api/index.js` — no framework
   preset needed.
3. Add the environment variables from `.env.example` under **Project
   Settings → Environment Variables**. At minimum you need `MONGO_URI` and
   `JWT_SECRET`; everything else has a safe default (mock payments, mock
   fantasy data, no demo user).
4. Set `CLIENT_ORIGIN` (or `CLIENT_ORIGINS`, comma-separated for multiple)
   to your frontend's deployed URL, with no trailing slash — this is what
   the app checks in its CORS `origin` callback.
5. Set `PUBLIC_API_URL` to this API's own deployed URL once you have it
   (used to build default Paynow callback URLs).
6. Deploy. Your API will be live at `https://<your-project>.vercel.app`,
   with every route still under `/api/...` exactly as before.

## 2. Cross-origin cookies

The app already sets `sameSite: 'none'` and `secure: true` for its session
cookie whenever `NODE_ENV === 'production'` (Vercel sets this
automatically), which is what's required for a frontend on a different
domain to receive and send the auth cookie. Just make sure both frontend and
backend are served over HTTPS (Vercel does this by default) and that
`CLIENT_ORIGIN(S)` exactly matches the frontend's origin.

## 3. Scheduled maintenance (Vercel Cron)

`server.js` already has a `/api/internal/cron/maintenance` route guarded by
a `CRON_SECRET` bearer check — it was clearly built with Vercel Cron in
mind, since Vercel automatically sends `Authorization: Bearer $CRON_SECRET`
to any path listed under `crons` in `vercel.json` when it invokes it.

- Set a `CRON_SECRET` environment variable in Vercel (any long random
  string — `openssl rand -base64 32` works well).
- `vercel.json` currently schedules it hourly (`0 * * * *`). **Vercel's
  Hobby plan only runs cron jobs once per day**, regardless of the schedule
  you set — upgrade to Pro (or adjust the schedule to `0 0 * * *` for a
  daily run) if you're on Hobby.
- Cron jobs only run on your production deployment, not preview deploys.
- This single job already covers subscription expiry, Paynow payment
  reconciliation, and league score syncing (see the route handler) — no
  extra cron entries are needed.

The original interval-based timers (`setInterval`) in `start()` still exist
for traditional Node hosting, but are automatically skipped when the
`VERCEL` environment variable is present (already handled by `server.js`'s
`IS_VERCEL` check) — they don't apply to serverless.

## 4. Local development

```bash
npm install
cp .env.example .env   # then fill in MONGO_URI and JWT_SECRET at minimum
npm run dev             # nodemon server.js, listens on PORT (default 8000)
```

You can also run it exactly as it will behave on Vercel using the Vercel
CLI:

```bash
npm install -g vercel
vercel dev
```

## 5. Notes carried over from the original app

- `PAYMENTS_MODE=mock` and `FPL_DATA_MODE=mock` are the safe defaults —
  switching either to `paynow` / `public` requires the matching
  `PAYNOW_*` credentials or a Node 18+ runtime with outbound network access
  (Vercel functions satisfy this already).
- `REAL_MONEY_ENABLED` is gated behind `LEGAL_APPROVAL_CONFIRMED`,
  `FANTASY_DATA_AUTHORIZED`, and `PAYMENT_PROVIDER_APPROVED` — this is
  enforced in `server.js` itself (`assertProductionSafetyGates()`) and is
  unchanged.
- There is no static-file/SPA hosting on Vercel (that block in `server.js`
  is skipped whenever `VERCEL` is set) — deploy your frontend as its own
  Vercel project (or wherever it already lives) and point it at this API's
  URL via `CLIENT_ORIGIN`.
