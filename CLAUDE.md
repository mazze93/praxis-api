# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Praxis is a Cloudflare Worker that enforces policy at the boundary between an AI
agent and the tools it can reach: it authenticates a session, resolves a policy
tier, verifies the caller, enforces allow-lists and quotas, dispatches to a
backend, and redacts the result. It sits on an authorization boundary, so treat
every change to `src/auth.ts`, `src/enforce.ts` and `src/policy.ts` as
security-sensitive (see `SECURITY.md`, "High-value review areas").

## Commands

```bash
npm ci                        # package-lock.json is committed; CI uses npm ci
npm run check                 # tsc --noEmit (src/ only)
npm test                      # vitest run (test/*.test.ts)
npx vitest run test/auth.test.ts          # one file
npx vitest run -t "fails closed"          # one test by name
cp .dev.vars.example .dev.vars && npm run dev   # wrangler dev on :8787
```

Seed the policy locally after `npm run dev` (the admin route fails closed if
`ADMIN_API_KEY` is unset or empty):

```bash
curl -sS http://localhost:8787/admin/policy/seed \
  -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" \
  --data-binary @seed/policy.json
```

`bruno/praxis-api/` is a Bruno collection covering each route (local and
production environments).

CI: `.github/workflows/verify.yml` runs `npm ci`, `check` and `test` on PRs and
pushes to `main`. `deploy.yml` is `workflow_dispatch` only.

## Deployment model

`wrangler.jsonc` deliberately contains `REPLACE_WITH_*_KV_ID` markers. Never
commit real ids. `npm run config:render` (`scripts/render-wrangler.mjs`) fills
them from six `*_KV_ID` / `*_KV_PREVIEW_ID` environment variables into
`.wrangler.generated.jsonc` (gitignored) and refuses to write if any marker
survives. Deploy with `--config .wrangler.generated.jsonc`. The deploy workflow
does this, then installs the five Worker secrets listed at the bottom of
`wrangler.jsonc`.

Identity API keys are looked up by name: identity `secure_pride` reads secret
`APIKEY_SECURE_PRIDE` (`verifyApiKey` uppercases and maps non-alphanumerics to
`_`). Adding an identity means a policy entry **and** a new secret in both
`.dev.vars.example`, `wrangler.jsonc`'s comment block and `deploy.yml`.

## Request pipeline (`POST /invoke-tool`)

`src/index.ts` `handleInvokeTool` is the whole enforcement path, in this order.
The order is load-bearing:

1. **Session.** A Bearer HS256 JWT from `/session/unlock` (`auth.ts`).
   `meta.identity` must equal the session `sub`.
2. **Tier resolution** (`policy.ts`). Identity → `identities[id].default_policy_set`;
   then `policy_matrix[set][identity][trigger]` → base tier; then
   `tool_overrides` (first match by `name` or `pattern`) can `force_tier`, or
   merge `quotas`/`redaction` into the tier. Any missing mapping throws: policy
   resolution fails closed, never to a default tier.
3. **Caller verification** (`enforce.ts`). The tier's `allow_callers` types;
   `require_signed_caller` checks an HMAC caller token bound to request_id,
   identity, caller type, tool name and tool_id; `require_human_approval`
   always throws (approval is a fail-closed stub).
4. **Allow-list.** `tool_names` or `tool_patterns` (regex from the policy).
5. **Quota.** Per `request_id` in `QUOTA_KV` (30-minute TTL).
6. **Dispatch** (`backends.ts`). `ToolRouter` matches the first registered rule.
   HTTP backends receive an `X-Praxis-Assertion` (HMAC, 30-second expiry,
   per-backend secret and audience). The contract a backend must implement is
   `docs/backend-contract.md`. Backends are registered in `buildRouter()` in
   `index.ts`; only the built-in `ping` exists.
7. **Byte quota, then redaction.** Redaction (pattern-based, block, or off) and
   UTF-8-safe truncation are applied after dispatch, before content reaches the
   model.

Every thrown error in steps 2–7 becomes a 403 (backend errors keep their own
safe message and status; details go only to `console.error`).

## Invariants and known limits

- **Expiry is validated as a finite number** (`auth.ts` `isUnexpired`). A bare
  `exp < now` check passed tokens with a missing or non-numeric `exp` forever;
  keep using the helper for any new token type.
- **Secret comparisons go through `constantTimeEqual`.**
- **KV is eventually consistent and not an atomic counter.** Quotas are a
  guardrail, not an exact limit (`SECURITY.md`).
- **Policy regexes are trusted input** (admin-authored); untrusted policy
  authors would be a ReDoS risk.
- **Open boundary issues, not yet decided** (reviewed 2026-10-28 in
  `mazze93/ai-behavior-research`, `docs/reviews/informed-consent-intercept-hook/`):
  - `meta.trigger` and `request_id` are caller-supplied. The trigger selects
    the tier and the caller token doesn't bind it; quotas are per `request_id`.
  - `/session/unlock` consumes the challenge but never uses its nonce, so the
    challenge adds rate limiting, not proof of possession.
  - Who mints caller tokens (`CALLER_HMAC_SECRET`) is undocumented. If the
    agent's own runtime holds that secret, caller verification is self-asserted.
