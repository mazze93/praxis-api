// Regression tests for the admin policy-seed route (index.ts requireAdmin).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index.ts";

const policy = readFileSync(new URL("../seed/policy.json", import.meta.url), "utf8");

function makeEnv(adminKey: string | undefined): Env {
  const store = new Map<string, string>();
  const kv = {
    get: async (key: string) => store.get(key) ?? null,
    put: async (key: string, value: string) => void store.set(key, value),
    delete: async (key: string) => void store.delete(key),
  } as unknown as KVNamespace;
  const env: Record<string, unknown> = {
    POLICY_KV: kv,
    SESSION_KV: kv,
    QUOTA_KV: kv,
    INVOKE_RATE_LIMITER: { limit: async () => ({ success: true }) },
    SESSION_JWT_SECRET: "s".repeat(32),
    CALLER_HMAC_SECRET: "c".repeat(32),
    SESSION_TTL_HOURS: "8",
  };
  if (adminKey !== undefined) env.ADMIN_API_KEY = adminKey;
  return env as Env;
}

async function seed(env: Env, authorization: string | null): Promise<number> {
  const headers = new Headers({ "content-type": "application/json" });
  if (authorization !== null) headers.set("authorization", authorization);
  const req = new Request("https://praxis.test/admin/policy/seed", { method: "POST", headers, body: policy });
  return (await worker.fetch(req, env)).status;
}

describe("POST /admin/policy/seed", () => {
  it("fails closed when ADMIN_API_KEY is unset, even for 'Bearer undefined'", async () => {
    const env = makeEnv(undefined);
    expect(await seed(env, "Bearer undefined")).toBe(401);
    expect(await seed(env, "Bearer ")).toBe(401);
    expect(await seed(env, null)).toBe(401);
  });

  it("fails closed when ADMIN_API_KEY is empty", async () => {
    expect(await seed(makeEnv(""), "Bearer ")).toBe(401);
  });

  it("accepts only the exact configured key", async () => {
    const env = makeEnv("admin-key-0123456789abcdef-0123456");
    expect(await seed(env, "Bearer admin-key-0123456789abcdef-0123456")).toBe(200);
    expect(await seed(env, "Bearer admin-key-0123456789abcdef-012345")).toBe(401);
    expect(await seed(env, "admin-key-0123456789abcdef-0123456")).toBe(401);
  });
});
