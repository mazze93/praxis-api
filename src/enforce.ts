// enforce.ts — Quota tracking (KV-backed), tier enforcement, caller verify, redaction
import type { TierDef } from "./policy.ts";
import { verifyCallerToken } from "./auth.ts";

// ── Quota (KV-backed, per request_id) ────────────────────────────────────────

interface QuotaState {
  calls_total: number;
  calls_by_tool: Record<string, number>;
  bytes_total: number;
}

const QUOTA_TTL = 1800; // 30 min in seconds

export async function applyQuotasOrThrow(
  kv: KVNamespace,
  requestId: string,
  toolName: string,
  tier: TierDef,
): Promise<void> {
  const q = tier.quotas ?? {};
  const maxTotal = q.max_calls_per_request ?? Infinity;
  const maxPerTool = q.max_calls_per_tool ?? Infinity;

  if (maxTotal === 0) throw new Error("Quota: tier allows 0 calls (DENY)");

  const key = `quota:${requestId}`;
  const raw = await kv.get(key, "text");
  const state: QuotaState = raw
    ? (JSON.parse(raw) as QuotaState)
    : { calls_total: 0, calls_by_tool: {}, bytes_total: 0 };

  const toolCount = (state.calls_by_tool[toolName] ?? 0) + 1;
  const totalCount = state.calls_total + 1;

  if (totalCount > maxTotal)
    throw new Error(`Quota exceeded: max ${maxTotal} calls per request`);
  if (toolCount > maxPerTool)
    throw new Error(`Quota exceeded: max ${maxPerTool} calls for tool "${toolName}"`);

  state.calls_total = totalCount;
  state.calls_by_tool[toolName] = toolCount;
  await kv.put(key, JSON.stringify(state), { expirationTtl: QUOTA_TTL });
}

export async function trackResponseBytes(
  kv: KVNamespace,
  requestId: string,
  bytes: number,
  tier: TierDef,
): Promise<void> {
  const max = tier.quotas?.max_response_bytes;
  if (!max) return;

  const key = `quota:${requestId}`;
  const raw = await kv.get(key, "text");
  if (!raw) return;
  const state = JSON.parse(raw) as QuotaState;
  state.bytes_total = (state.bytes_total ?? 0) + bytes;

  if (state.bytes_total > max)
    throw new Error(`Response byte quota exceeded: max ${max} bytes returned per request`);

  await kv.put(key, JSON.stringify(state), { expirationTtl: QUOTA_TTL });
}

// ── Tier enforcement ─────────────────────────────────────────────────────────

export function toolAllowedOrThrow(toolName: string, tier: TierDef): void {
  const allow = tier.allow ?? {};
  const byName = (allow.tool_names ?? []).includes(toolName);
  const byPattern = (allow.tool_patterns ?? []).some((pat) => new RegExp(pat).test(toolName));
  if (!byName && !byPattern) {
    throw new Error(`Tool "${toolName}" not permitted by active tier`);
  }
}

// ── Caller verification ──────────────────────────────────────────────────────

export interface Caller {
  type: "model" | "code_execution";
  tool_id?: string;
  signed_token?: string;
}

export async function callerVerificationOrThrow(
  caller: Caller | undefined,
  callersRule: TierDef["callers"],
  hmacSecret: string,
  expected: { requestId: string; identity: string; toolName: string },
): Promise<void> {
  const allowCallers = callersRule?.allow_callers ?? [];
  const requireSigned = callersRule?.require_signed_caller ?? false;
  const c: Caller = caller ?? { type: "model" };

  const allowed = allowCallers.some((x) => x.type === c.type);
  if (!allowed) throw new Error(`Caller type "${c.type}" not permitted by this tier`);

  if (c.type === "code_execution" && !c.tool_id) {
    throw new Error("code_execution caller must include tool_id");
  }

  if (requireSigned) {
    const result = await verifyCallerToken(c.signed_token ?? "", hmacSecret, {
      requestId: expected.requestId,
      identity: expected.identity,
      callerType: c.type,
      toolName: expected.toolName,
      toolId: c.tool_id,
    });
    if (!result.ok) throw new Error(`Caller token verification failed: ${result.reason}`);
  }

  if (callersRule?.require_human_approval) {
    throw new Error(
      "Human approval required for this tier — POST /approve/:request_id (not yet implemented).",
    );
  }
}

// ── Redaction ────────────────────────────────────────────────────────────────

function utf8SafeTruncate(str: string, maxBytes: number): string {
  const enc = new TextEncoder();
  const buf = enc.encode(str);
  if (buf.byteLength <= maxBytes) return str;
  // Walk back to a valid UTF-8 boundary
  let i = maxBytes;
  while (i > 0 && (buf[i]! & 0xc0) === 0x80) i--;
  return new TextDecoder().decode(buf.slice(0, i)) + "\n[TRUNCATED BY POLICY]";
}

export function redactOutput(raw: string, redaction: TierDef["redaction"]): string {
  if (!redaction || redaction.mode === "off") return raw;
  if (redaction.mode === "block") return "[BLOCKED BY POLICY]";

  let out = raw;
  for (const p of redaction.patterns ?? []) {
    out = out.replace(new RegExp(p.regex, (p.flags ?? "") + "g"), `[REDACTED:${p.name}]`);
  }
  const max = redaction.max_output_bytes_to_model ?? 100_000;
  return utf8SafeTruncate(out, max);
}
