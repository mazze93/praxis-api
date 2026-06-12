/**
 * praxis-api — Cloudflare Worker
 * Agentic trust enforcement layer for the Praxis Sovereignty Stack.
 *
 * Routes:
 *   GET  /health                 — liveness probe, no auth
 *   POST /session/challenge      — request a nonce for API key auth
 *   POST /session/unlock         — exchange challenge+key for session JWT
 *   GET  /session                — validate current session token
 *   GET  /policy                 — current policy summary (authenticated)
 *   POST /admin/policy/seed      — load new policy document (admin auth)
 *   POST /invoke-tool            — policy-gated tool invocation (session auth)
 */

import { verifyApiKey, issueSessionToken, verifyJwt, createChallenge, consumeChallenge } from "./auth.ts";
import type { SessionPayload } from "./auth.ts";
import { loadPolicy, storePolicy, resolvePolicySetId, resolveTierId, resolveEffectiveTier, listPolicySets } from "./policy.ts";
import { applyQuotasOrThrow, trackResponseBytes, toolAllowedOrThrow, callerVerificationOrThrow, redactOutput } from "./enforce.ts";
import type { Caller } from "./enforce.ts";
import { ToolRouter, BackendError } from "./backends.ts";

export interface Env {
  POLICY_KV: KVNamespace;
  SESSION_KV: KVNamespace;
  QUOTA_KV: KVNamespace;
  INVOKE_RATE_LIMITER: RateLimit;
  SESSION_JWT_SECRET: string;
  CALLER_HMAC_SECRET: string;
  ADMIN_API_KEY: string;
  SESSION_TTL_HOURS: string; // coerced to number
  // Identity API keys — APIKEY_<IDENTITY_UPPER>
  [key: string]: unknown;
}

// ── Tool router — register backends here ─────────────────────────────────────
// Example:
//   router.register({ match: /^search_/, backend: { type: "http", baseUrl: env.SEARCH_URL, ... } });
//   router.register({ match: "ping", backend: { type: "local", handler: async () => ({ pong: true }) } });
function buildRouter(_env: Env): ToolRouter {
  const router = new ToolRouter();
  // Built-in ping for smoke testing
  router.register({
    match: "ping",
    backend: { type: "local", handler: async () => ({ pong: true }) },
  });
  return router;
}

// ── Response helpers ─────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}

function err(message: string, status: number): Response {
  return json({ ok: false, error: message }, status);
}

// ── Session middleware ────────────────────────────────────────────────────────

async function requireSession(
  req: Request,
  env: Env,
): Promise<SessionPayload | Response> {
  const auth = req.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return err("Missing or invalid Authorization header", 401);
  try {
    return await verifyJwt<SessionPayload>(auth.slice(7), env.SESSION_JWT_SECRET);
  } catch (e) {
    return err(`Session invalid: ${e instanceof Error ? e.message : e}`, 401);
  }
}

// ── Admin middleware ──────────────────────────────────────────────────────────

function requireAdmin(req: Request, env: Env): boolean {
  const auth = req.headers.get("Authorization");
  return auth === `Bearer ${env.ADMIN_API_KEY}`;
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async function handleHealth(): Promise<Response> {
  return json({ ok: true, service: "praxis-api" });
}

async function handleChallenge(req: Request, env: Env): Promise<Response> {
  const { identity } = await req.json<{ identity: string }>();
  if (!identity || typeof identity !== "string") return err("identity required", 400);

  // Rate limit: 10 challenges/min per IP
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await env.INVOKE_RATE_LIMITER.limit({ key: `challenge:${ip}` });
  if (!rl.success) return err("Rate limit exceeded — try again in a moment", 429);

  const { challenge_id, nonce } = await createChallenge(env.SESSION_KV, identity);
  return json({ ok: true, challenge_id, nonce, ttl_seconds: 300 });
}

async function handleUnlock(req: Request, env: Env): Promise<Response> {
  const body = await req.json<{ challenge_id: string; identity: string; api_key: string }>();
  const { challenge_id, identity, api_key } = body;

  if (!challenge_id || !identity || !api_key) {
    return err("challenge_id, identity, and api_key required", 400);
  }

  const nonce = await consumeChallenge(env.SESSION_KV, challenge_id, identity);
  if (!nonce) return err("Challenge not found, expired, or identity mismatch", 401);

  const valid = await verifyApiKey(env as unknown as Record<string, string>, identity, api_key);
  if (!valid) return err("Invalid API key for identity", 401);

  const ttlHours = Math.max(1, parseInt(env.SESSION_TTL_HOURS ?? "8", 10));
  const token = await issueSessionToken(identity, env.SESSION_JWT_SECRET, ttlHours);
  return json({ ok: true, token, ttl_hours: ttlHours });
}

async function handleSessionValidate(req: Request, env: Env): Promise<Response> {
  const session = await requireSession(req, env);
  if (session instanceof Response) return session;
  return json({ ok: true, identity: session.sub, exp: session.exp });
}

async function handleGetPolicy(req: Request, env: Env): Promise<Response> {
  const session = await requireSession(req, env);
  if (session instanceof Response) return session;
  try {
    const policy = await loadPolicy(env.POLICY_KV);
    return json({
      ok: true,
      version: policy.version,
      policy_sets: listPolicySets(policy),
      identities: Object.keys(policy.identities),
      tiers: Object.keys(policy.tiers),
    });
  } catch (e) {
    return err(e instanceof Error ? e.message : "Policy load failed", 503);
  }
}

async function handleSeedPolicy(req: Request, env: Env): Promise<Response> {
  if (!requireAdmin(req, env)) return err("Admin authentication required", 401);
  try {
    const policy = await req.json();
    await storePolicy(env.POLICY_KV, policy);
    return json({ ok: true, message: "Policy stored successfully" });
  } catch (e) {
    return err(e instanceof Error ? e.message : "Policy invalid", 400);
  }
}

async function handleInvokeTool(req: Request, env: Env): Promise<Response> {
  const session = await requireSession(req, env);
  if (session instanceof Response) return session;

  // Rate limit: 60 invocations/min per identity
  const rl = await env.INVOKE_RATE_LIMITER.limit({ key: `invoke:${session.sub}` });
  if (!rl.success) return err("Rate limit exceeded", 429);

  let body: {
    request_id: string;
    tool_name: string;
    input: unknown;
    caller?: Caller;
    meta: { identity: string; trigger: string };
  };
  try {
    body = await req.json();
  } catch {
    return err("Invalid JSON body", 400);
  }

  const { request_id, tool_name, input, caller, meta } = body;
  if (!request_id || !tool_name || !meta?.identity || !meta?.trigger) {
    return err("request_id, tool_name, meta.identity, meta.trigger required", 400);
  }

  // Identity must match session — model cannot escalate
  if (meta.identity !== session.sub) {
    return err(
      `Identity mismatch: session is "${session.sub}", request claims "${meta.identity}"`,
      403,
    );
  }

  const router = buildRouter(env);

  try {
    const policy = await loadPolicy(env.POLICY_KV);
    const policySetId = resolvePolicySetId(policy, meta.identity);
    const baseTierId = resolveTierId(policy, policySetId, meta.identity, meta.trigger);
    const { tierId, tier } = resolveEffectiveTier(policy, baseTierId, tool_name);

    // 1. Caller verification
    await callerVerificationOrThrow(caller, tier.callers, env.CALLER_HMAC_SECRET, {
      requestId: request_id,
      identity: meta.identity,
      toolName: tool_name,
    });

    // 2. Tool allow/deny
    toolAllowedOrThrow(tool_name, tier);

    // 3. Quota check + increment
    await applyQuotasOrThrow(env.QUOTA_KV, request_id, tool_name, tier);

    // 4. Backend dispatch
    const result = await router.dispatch(tool_name, input, {
      requestId: request_id,
      identity: meta.identity,
      policySetId,
      tierId,
      callerType: caller?.type ?? "model",
    });

    const rawText = typeof result === "string" ? result : JSON.stringify(result);

    // 5. Byte tracking + redaction
    await trackResponseBytes(env.QUOTA_KV, request_id, rawText.length, tier);
    const safeText = redactOutput(rawText, tier.redaction);

    return json({
      ok: true,
      policy: { policy_set_id: policySetId, tier_id: tierId },
      tool_name,
      content: safeText,
    });
  } catch (e) {
    if (e instanceof BackendError) {
      console.error(
        `[praxis-api] backend error request_id=${request_id} tool=${tool_name}`,
        e.internalDetail ?? e.message,
      );
      return err(e.safeMessage, e.statusCode);
    }
    const msg = e instanceof Error ? e.message : "Request denied by policy";
    return err(msg, 403);
  }
}

// ── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method;

    if (method === "GET" && pathname === "/health") return handleHealth();

    if (method === "POST" && pathname === "/session/challenge")
      return handleChallenge(req, env);
    if (method === "POST" && pathname === "/session/unlock")
      return handleUnlock(req, env);
    if (method === "GET" && pathname === "/session")
      return handleSessionValidate(req, env);

    if (method === "GET" && pathname === "/policy")
      return handleGetPolicy(req, env);
    if (method === "POST" && pathname === "/admin/policy/seed")
      return handleSeedPolicy(req, env);

    if (method === "POST" && pathname === "/invoke-tool")
      return handleInvokeTool(req, env);

    return err("Not found", 404);
  },
} satisfies ExportedHandler<Env>;
