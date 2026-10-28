// Regression tests for token expiry and constant-time comparison (auth.ts).
import { describe, expect, it } from "vitest";
import { constantTimeEqual, isUnexpired, signJwt, verifyCallerToken, verifyJwt } from "../src/auth.ts";

const SECRET = "caller-secret-0123456789abcdef-0123";
const now = () => Math.floor(Date.now() / 1000);
const b64url = (s: string) => Buffer.from(s).toString("base64url");

async function sign(payloadB64: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${Buffer.from(sig).toString("base64url")}`;
}

const expected = { requestId: "r1", identity: "daedalus", callerType: "model" as const, toolName: "create_ticket" };
const base = { request_id: "r1", identity: "daedalus", caller_type: "model", tool_name: "create_ticket", iat: now() };

describe("verifyCallerToken expiry", () => {
  it("accepts a correctly signed, unexpired token", async () => {
    const token = await sign(b64url(JSON.stringify({ ...base, exp: now() + 60 })));
    expect(await verifyCallerToken(token, SECRET, expected)).toEqual({ ok: true });
  });

  it.each([
    ["missing", undefined],
    ["a string", "never"],
    ["null", null],
    ["a numeric string", String(now() + 60)],
    ["in the past", now() - 1],
  ])("rejects a token whose exp is %s", async (_label, exp) => {
    const token = await sign(b64url(JSON.stringify({ ...base, exp })));
    expect((await verifyCallerToken(token, SECRET, expected)).ok).toBe(false);
  });
});

describe("verifyJwt expiry", () => {
  it("rejects a validly signed JWT with no exp", async () => {
    const token = await signJwt({ sub: "daedalus" }, SECRET);
    await expect(verifyJwt(token, SECRET)).rejects.toThrow("token expired");
  });

  it("accepts a validly signed JWT that has not expired", async () => {
    const token = await signJwt({ sub: "daedalus", exp: now() + 60 }, SECRET);
    await expect(verifyJwt<{ exp: number; sub: string }>(token, SECRET)).resolves.toMatchObject({ sub: "daedalus" });
  });
});

describe("isUnexpired", () => {
  it("treats the expiry second itself as still valid, matching the original boundary", () => {
    expect(isUnexpired(100, 100)).toBe(true);
    expect(isUnexpired(99, 100)).toBe(false);
  });
});

describe("constantTimeEqual", () => {
  it("compares by value, including across different lengths", async () => {
    expect(await constantTimeEqual("same-secret", "same-secret")).toBe(true);
    expect(await constantTimeEqual("same-secret", "same-secreT")).toBe(false);
    expect(await constantTimeEqual("short", "a-much-longer-secret")).toBe(false);
    expect(await constantTimeEqual("", "")).toBe(true);
  });
});
