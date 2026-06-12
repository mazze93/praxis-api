// policy.ts — Policy loading from KV, resolution, type definitions
// Policy document is stored as JSON in POLICY_KV under key "policy:v1".
// The schema mirrors praxis-aegis/tool_risk_tier.yaml exactly.

export interface TierDef {
  description: string;
  allow: { tool_names?: string[]; tool_patterns?: string[] };
  quotas: {
    max_calls_per_request?: number;
    max_calls_per_tool?: number;
    max_parallel?: number;
    max_response_bytes?: number;
  };
  callers?: {
    allow_callers?: Array<{ type: string }>;
    require_signed_caller?: boolean;
    require_human_approval?: boolean;
  };
  redaction: {
    mode: "off" | "block" | "patterns";
    max_output_bytes_to_model?: number;
    patterns?: Array<{ name: string; regex: string; flags?: string }>;
  };
}

export interface ToolOverride {
  match: { name?: string; pattern?: string };
  force_tier?: string;
  reason?: string;
  quotas?: Partial<TierDef["quotas"]>;
  redaction?: Partial<TierDef["redaction"]>;
}

export interface PolicyDoc {
  version: number;
  policy_sets: Array<{ id: string; label: string }>;
  identities: Record<string, { label: string; default_policy_set: string }>;
  triggers: Record<string, { label: string }>;
  tiers: Record<string, TierDef>;
  policy_matrix: Record<string, Record<string, Record<string, string>>>;
  tool_overrides: ToolOverride[];
}

// ── Validation ────────────────────────────────────────────────────────────────

function validatePolicy(policy: PolicyDoc): void {
  for (const [tierId, tier] of Object.entries(policy.tiers)) {
    if (!tierId.includes("DENY")) continue;
    const names = tier.allow?.tool_names ?? [];
    const patterns = tier.allow?.tool_patterns ?? [];
    if (names.length > 0 || patterns.length > 0) {
      throw new Error(
        `Policy integrity: DENY tier "${tierId}" has non-empty allow lists — this would silently permit tools.`,
      );
    }
  }
  // Validate redaction regexes compile
  for (const [tierId, tier] of Object.entries(policy.tiers)) {
    for (const p of tier.redaction.patterns ?? []) {
      try {
        new RegExp(p.regex, p.flags ?? "g");
      } catch (e) {
        throw new Error(`Policy regex error in tier "${tierId}" pattern "${p.name}": ${e}`);
      }
    }
  }
}

// ── KV loading ───────────────────────────────────────────────────────────────

const POLICY_KEY = "policy:v1";

export async function loadPolicy(kv: KVNamespace): Promise<PolicyDoc> {
  const raw = await kv.get(POLICY_KEY, "text");
  if (!raw) throw new Error("No policy document found in KV. Seed with POST /admin/policy/seed.");
  const policy = JSON.parse(raw) as PolicyDoc;
  validatePolicy(policy);
  return policy;
}

export async function storePolicy(kv: KVNamespace, policy: PolicyDoc): Promise<void> {
  validatePolicy(policy);
  await kv.put(POLICY_KEY, JSON.stringify(policy));
}

// ── Resolution ───────────────────────────────────────────────────────────────

function findOverride(policy: PolicyDoc, toolName: string): ToolOverride | null {
  for (const o of policy.tool_overrides ?? []) {
    const m = o.match ?? {};
    if (m.name && m.name === toolName) return o;
    if (m.pattern && new RegExp(m.pattern).test(toolName)) return o;
  }
  return null;
}

function mergeTier(tier: TierDef, override: ToolOverride): TierDef {
  return {
    ...tier,
    quotas: { ...tier.quotas, ...(override.quotas ?? {}) },
    redaction: { ...tier.redaction, ...(override.redaction ?? {}) },
  };
}

export interface ResolvedTier {
  tierId: string;
  tier: TierDef;
  override: ToolOverride | null;
}

export function resolvePolicySetId(policy: PolicyDoc, identity: string): string {
  const id = policy.identities?.[identity]?.default_policy_set;
  if (!id) throw new Error(`No default_policy_set for identity="${identity}"`);
  return id;
}

export function resolveTierId(
  policy: PolicyDoc,
  policySetId: string,
  identity: string,
  trigger: string,
): string {
  const tier = policy.policy_matrix?.[policySetId]?.[identity]?.[trigger];
  if (!tier) {
    throw new Error(
      `No tier mapping for policy_set="${policySetId}" identity="${identity}" trigger="${trigger}"`,
    );
  }
  return tier;
}

export function resolveEffectiveTier(
  policy: PolicyDoc,
  baseTierId: string,
  toolName: string,
): ResolvedTier {
  const override = findOverride(policy, toolName);
  if (override?.force_tier) {
    const forced = policy.tiers?.[override.force_tier];
    if (!forced) throw new Error(`Override references unknown tier: ${override.force_tier}`);
    return { tierId: override.force_tier, tier: forced, override };
  }
  const tier = policy.tiers?.[baseTierId];
  if (!tier) throw new Error(`Unknown tier: ${baseTierId}`);
  return { tierId: baseTierId, tier: override ? mergeTier(tier, override) : tier, override };
}

export function listPolicySets(policy: PolicyDoc) {
  return (policy.policy_sets ?? []).map((p) => ({ id: p.id, label: p.label }));
}
