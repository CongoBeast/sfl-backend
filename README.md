# Supreme Fantasy League API (with email notifications)

Express + MongoDB backend, packaged to deploy on Vercel as a single serverless
function — same approach as before, now built from the fuller `server_local.js`
(renamed to `server.js` here) with `local-email-service.js` wired in for
Resend-powered transactional email.

## What's the same as before

`api/index.js`, `vercel.json`, `package.json` (no new npm dependencies —
both the email and Cloudinary integrations use native `fetch`, not an SDK),
`.gitignore`, and the overall deploy steps are unchanged from the previous
package. See those sections below if you skipped the first round.

## The one code change made to `server.js`, and why

This version added a much stricter startup check, `validateRuntimeConfiguration()`,
that's supposed to block a genuinely-live, real-money deployment from running
with mock payments, demo data, missing legal sign-off, etc. As written, it
was keyed off `IS_PRODUCTION` alone:

```js
if (IS_PRODUCTION) {
  const problems = [];
  if (MOCK_PAYMENTS || !PAYNOW_PAYMENTS) problems.push('PAYMENTS_MODE must be paynow');
  // ...
```

**The problem:** Vercel sets `NODE_ENV=production` for every deployment it
builds — Preview deployments included, not just the one you promote to
Production. `IS_PRODUCTION` is therefore always `true` on Vercel, with no
way to distinguish "this is a real live launch" from "I'm still testing on
Vercel with mock payments and demo data," which is exactly the workflow
we've been using this whole time. Left as-is, this would make every request
return 503 forever on Vercel, because `prepareRuntime()` calls
`connectDatabase()`, which calls this function, and it would throw before a
single request could be served — using the same mock/demo-friendly env vars
that have worked fine up to now.

**The fix**, in `server.js`:
```diff
- if (IS_PRODUCTION) {
+ if (IS_PRODUCTION && String(process.env.REAL_MONEY_ENABLED || '').trim().toLowerCase() === 'true') {
    const problems = [];
```
Now this checklist only activates once you deliberately set
`REAL_MONEY_ENABLED=true` — the same flag the codebase already uses
elsewhere as its "we are actually going live" switch (there's a second,
earlier gate, `assertProductionSafetyGates()`, that was already correctly
keyed off `REAL_MONEY_ENABLED` rather than `IS_PRODUCTION` — only the newer
one needed this fix). Everything else about `IS_PRODUCTION` (cookie
`SameSite`/`Secure` attributes, hiding stack traces on 500s, disabling
static file serving on Vercel) is untouched and still correctly tied to
`NODE_ENV`.

**What this means for you:** keep `REAL_MONEY_ENABLED=false` for as long as
you're testing/building (mock payments and mock fantasy data work exactly
as before, on Vercel or locally). Only set it to `true` once
`PAYMENTS_MODE=paynow`, `PAYNOW_TEST_MODE=false`, `FPL_DATA_MODE=public`,
`LEGAL_APPROVAL_CONFIRMED=true`, `FANTASY_DATA_AUTHORIZED=true`,
`PAYMENT_PROVIDER_APPROVED=true`, and everything else in the "Real-money
production safety gates" section of `.env.example` is genuinely true — at
that point both gates enforce the full checklist, exactly as originally
designed.

I verified all three states directly: `NODE_ENV=production` with
`REAL_MONEY_ENABLED` unset now starts up fine (fails only on the DB
connection in my test, as expected with a fake URI) — while
`REAL_MONEY_ENABLED=true` with the rest of the checklist still incomplete
correctly still throws and refuses to start.

## Email notifications (new in this version)

`local-email-service.js` sends real transactional email via Resend for
welcome, payment status changes, league join/creation/results, support
tickets, and stale-team reminders — always to the real customer's own
registered email address (see the earlier email-audit answer for the full
breakdown).

Two things to know operationally:

- **If `EMAILS_ENABLED=true`, `RESENDER_API_KEY` and `SENDING_EMAIL` are
  required or the app won't start at all** — this check happens at module
  load time (`createLocalEmailService` throws immediately if they're
  missing), before any request is served. Leave `EMAILS_ENABLED=false`
  (the default in `.env.example`) until you actually have a Resend account
  and a verified sending domain.
- `ADMIN_NOTIFICATION_EMAIL` is optional while `REAL_MONEY_ENABLED=false`,
  but becomes required (and validated as a real email address) once you
  flip that on.

## Deploy steps (same as before)

1. Push to GitHub, import into Vercel — it auto-detects the Node.js runtime
   from `api/index.js`.
2. Add the environment variables from `.env.example`. At minimum:
   `MONGO_URI`, `JWT_SECRET` (32+ characters in this version), and
   `CLIENT_ORIGIN(S)` set to your actual frontend origin(s).
3. Everything payments/email/fantasy-data-related defaults to mock/off —
   safe to deploy immediately without Paynow, Resend, or Cloudinary
   credentials.
4. Deploy. Cron (`vercel.json`) is scheduled daily
   (`/api/internal/cron/maintenance`, `0 0 * * *`) to stay within the
   Hobby plan's once-per-day limit — tighten it if you're on Pro. Set
   `CRON_SECRET` to match what Vercel will send as
   `Authorization: Bearer $CRON_SECRET`.

## Local development

```bash
npm install
cp .env.example .env
npm run dev
```

Note: there's a harmless startup warning — `Duplicate schema index on
{"inviteCode":1}` — from a Mongoose index declared both via `index: true`
and a separate `schema.index()` call. It doesn't affect behavior, just
worth cleaning up in the League schema at some point if the log noise
bothers you.
