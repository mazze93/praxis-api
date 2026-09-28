# praxis-api

Policy enforcement at the boundary between an AI agent and the tools it can reach.

Praxis is a small Cloudflare Worker that turns identity, execution context, and a versioned policy document into an enforceable decision before a tool call leaves the gateway. It is deliberately narrower than an agent framework: it authenticates sessions, resolves a policy tier, verifies the caller, enforces allow-lists and quotas, dispatches to a backend, and redacts the result.

> **Status:** experimental security infrastructure. The policy path is implemented; downstream adapters are intentionally explicit rather than hidden behind framework magic.

## Why this exists

Agent permissions are usually scattered across prompts, OAuth scopes, application code, and human convention. Praxis makes one part of that boundary inspectable:

```text
agent / code execution
        │
        ▼
  session identity
        │
        ▼
 identity × trigger ──► policy set ──► risk tier
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                    caller proof   quotas      allow/deny
                         │            │            │
                         └────────────┼────────────┘
                                      ▼
                               backend dispatch
                                      │
                                      ▼
                                  redaction
                                      │
                                      ▼
                                    result
```

## Implemented surface

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | liveness |
| `POST /session/challenge` | none + rate limit | single-use authentication challenge |
| `POST /session/unlock` | API key + challenge | exchange for an 8-hour HS256 session JWT |
| `GET /session` | session | validate current session |
| `GET /policy` | session | inspect policy metadata |
| `POST /admin/policy/seed` | admin bearer key | validate and store the active policy |
| `POST /invoke-tool` | session + signed caller | enforce policy and dispatch a tool |

The seed policy ships with three policy sets, four tiers, explicit destructive-operation denial, response quotas, and output redaction.

## Security properties

- **Identity cannot self-escalate:** request identity must equal the authenticated session subject.
- **Caller assertions can be signed:** model/code-execution provenance is bound to request ID, identity, tool and expiry.
- **Policy fails closed:** unknown identity/trigger/tier/tool mappings throw rather than defaulting permissive.
- **DENY tiers are integrity-checked:** a DENY tier with a non-empty allow-list is rejected.
- **Challenges are single-use and expire after five minutes.**
- **Backend assertions are short-lived:** downstream calls receive a signed 30-second Praxis assertion.
- **Output controls happen after dispatch:** byte quotas and redaction are applied before content returns to the model.

### Known limits

KV is eventually consistent and is not an atomic counter. The current quota implementation is appropriate as a guardrail, not as a billing-grade or adversarially exact rate limiter. Human approval is deliberately a stub and currently fails closed. See [SECURITY.md](SECURITY.md).

## Local development

Requirements: Node.js 20+ and a Cloudflare account for remote deployment.

```zsh
npm ci
cp .dev.vars.example .dev.vars
npm run check
npm run dev
```

Seed the local policy:

```zsh
curl -sS http://localhost:8787/admin/policy/seed \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @seed/policy.json
```

Then use the Bruno collection under `bruno/praxis-api` or call the session routes directly.

## Cloudflare deployment

Praxis requires three KV namespaces:

- `POLICY_KV` — active policy document
- `SESSION_KV` — authentication challenges
- `QUOTA_KV` — per-request guardrail state

Create production and preview namespaces, then store their IDs as GitHub Actions repository variables:

```text
POLICY_KV_ID
POLICY_KV_PREVIEW_ID
SESSION_KV_ID
SESSION_KV_PREVIEW_ID
QUOTA_KV_ID
QUOTA_KV_PREVIEW_ID
```

Store these repository secrets:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
SESSION_JWT_SECRET
CALLER_HMAC_SECRET
ADMIN_API_KEY
APIKEY_DAEDALUS
APIKEY_SECURE_PRIDE
```

The deploy workflow renders a temporary Wrangler configuration from those values, checks the TypeScript build, deploys, then installs Worker secrets. No resource IDs or credentials are committed.

For a workstation deployment, export the six KV IDs and run:

```zsh
npm run config:render
npx wrangler deploy --config .wrangler.generated.jsonc
```

## Downstream contract

Praxis does not assume that every service already speaks its protocol. A downstream tool adapter accepts:

```http
POST /invoke-tool
X-Praxis-Assertion: <signed assertion>
X-Request-Id: <request id>
Content-Type: application/json

{
  "tool_name": "search_repositories",
  "input": { "...": "..." }
}
```

The backend must verify the assertion signature, audience, expiry, request ID, identity and tool name before performing the operation.

The precise contract is documented in [docs/backend-contract.md](docs/backend-contract.md).

## Where it fits

Praxis is most useful as a **policy plane**, not as another monolith.

- **github-mcp-gateway:** Praxis can become the authorization front-door for selected GitHub tool calls. The gateway currently exposes MCP/OAuth, not `/invoke-tool`, so this needs a deliberately small adapter rather than URL glue.
- **Stratum:** Praxis can decide whether an event-producing action is allowed; Stratum remains the provenance/ledger plane that records what happened.
- **Stele:** Stele can consume Praxis decisions as runtime integrity evidence while remaining responsible for model-session governance.
- **Opportunity Ledger:** read/search operations are a good first low-risk integration; application mutations should remain separately approval-gated.
- **Secure Pride:** the existing paranoid policy set is a useful reference profile for constrained client deployments.

That separation is the useful architecture: **Praxis decides, the service acts, Stratum records.**

## Repository map

```text
src/
  auth.ts       challenge, JWT and caller-token verification
  policy.ts     policy schema, validation and tier resolution
  enforce.ts    allow-lists, quotas, caller verification, redaction
  backends.ts   signed backend dispatch
  index.ts      HTTP routes and orchestration
seed/
  policy.json   example policy document
bruno/
  praxis-api/   API request collection
scripts/
  render-wrangler.mjs
```

## Public-release checklist

- [x] no production secrets committed
- [x] example environment file only
- [x] Apache-2.0 licensing aligned with the adjacent gateway project
- [x] CI type-check
- [x] deployment path keeps account IDs outside source
- [ ] complete external security review before treating it as a security boundary
- [ ] implement durable human approval before enabling privileged tiers
- [ ] move strict quota accounting to a Durable Object if adversarial concurrency matters

## License

Apache-2.0.
