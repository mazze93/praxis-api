// auth.ts — JWT session management via crypto.subtle (no library)
// Sessions: API key → challenge → session JWT (HS256)
// Challenges stored in SESSION_KV with TTL. Single-use.

export interface SessionPayload {
  sub: string; // identity
  jti: string;
  iat: number;
  exp: number;
}

// ── Codec helpers ────────────────────────────────────────────────────────────

function b64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeB64url(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((s.length + 3) & 3);
  const raw = atob(padded);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

// Static header — HS256 JWT
const HDR = b64url(new TextEncoder().encode('{"alg":"HS256","typ":"JWT"}').buffer as ArrayBuffer);

// ── JWT ──────────────────────────────────────────────────────────────────────

export async function signJwt(
  payload: Record<string, unknown>,
  secret: string,
): Promise<string> {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)).buffer as ArrayBuffer);
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${HDR}.${body}`),
  );
  return `${HDR}.${body}.${b64url(sig)}`;
}

export async function verifyJwt<T extends { exp: number }>(
  token: string,
  secret: string,
): Promise<T> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [hdr, body, sig] = parts as [string, string, string];
  const key = await hmacKey(secret);
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    decodeB64url(sig),
    new TextEncoder().encode(`${hdr}.${body}`),
  );
  if (!ok) throw new Error("invalid signature");
  const payload = JSON.parse(new TextDecoder().decode(decodeB64url(body))) as T;
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error("token expired");
  return payload;
}

export async function issueSessionToken(
  identity: string,
  secret: string,
  ttlHours = 8,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    { sub: identity, jti: crypto.randomUUID(), iat: now, exp: now + ttlHours * 3600 },
    secret,
  );
}

// ── Challenge store (KV-backed, TTL 300s) ───────────────────────────────────

export interface ChallengeRecord {
  identity: string;
  nonce: string;
}

export async function createChallenge(
  kv: KVNamespace,
  identity: string,
  ttlSeconds = 300,
): Promise<{ challenge_id: string; nonce: string }> {
  const challenge_id = crypto.randomUUID();
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer);
  await kv.put(
    `challenge:${challenge_id}`,
    JSON.stringify({ identity, nonce } satisfies ChallengeRecord),
    { expirationTtl: ttlSeconds },
  );
  return { challenge_id, nonce };
}

export async function consumeChallenge(
  kv: KVNamespace,
  challenge_id: string,
  identity: string,
): Promise<string | null> {
  const key = `challenge:${challenge_id}`;
  const raw = await kv.get(key);
  if (!raw) return null;
  const rec = JSON.parse(raw) as ChallengeRecord;
  if (rec.identity !== identity) return null;
  await kv.delete(key); // single-use
  return rec.nonce;
}

// ── API key verification ─────────────────────────────────────────────────────
// Each identity's API key is stored as a Worker secret: APIKEY_<IDENTITY_UPPER>
// Verification uses constant-time HMAC comparison to avoid timing attacks.

export async function verifyApiKey(
  env: Record<string, string>,
  identity: string,
  providedKey: string,
): Promise<boolean> {
  const envVar = `APIKEY_${identity.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
  const expected = env[envVar];
  if (!expected) return false;
  // Constant-time comparison via HMAC
  const key = await hmacKey("apikey-comparison-constant-time");
  const a = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(providedKey));
  const b = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(expected));
  const av = new Uint8Array(a);
  const bv = new Uint8Array(b);
  if (av.length !== bv.length) return false;
  let diff = 0;
  for (let i = 0; i < av.length; i++) diff |= av[i]! ^ bv[i]!;
  return diff === 0;
}

// ── Caller HMAC token ────────────────────────────────────────────────────────
// Format: base64url(JSON payload) + "." + base64url(HMAC-SHA256 signature)

export interface CallerTokenPayload {
  request_id: string;
  identity: string;
  caller_type: "model" | "code_execution";
  tool_name: string;
  tool_id?: string;
  iat: number;
  exp: number;
}

export async function verifyCallerToken(
  token: string,
  secret: string,
  expected: {
    requestId: string;
    identity: string;
    callerType: "model" | "code_execution";
    toolName: string;
    toolId?: string;
  },
): Promise<{ ok: boolean; reason?: string }> {
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed token" };
  const [payloadB64, sigB64] = parts as [string, string];

  const key = await hmacKey(secret);
  const expectedSig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payloadB64),
  );
  const providedSig = decodeB64url(sigB64);
  const expectedBytes = new Uint8Array(expectedSig);

  if (providedSig.length !== expectedBytes.length) return { ok: false, reason: "signature invalid" };
  let diff = 0;
  for (let i = 0; i < providedSig.length; i++) diff |= providedSig[i]! ^ expectedBytes[i]!;
  if (diff !== 0) return { ok: false, reason: "signature invalid" };

  let payload: CallerTokenPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(decodeB64url(payloadB64))) as CallerTokenPayload;
  } catch {
    return { ok: false, reason: "payload not valid JSON" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) return { ok: false, reason: "token expired" };
  if (payload.request_id !== expected.requestId) return { ok: false, reason: "request_id mismatch" };
  if (payload.identity !== expected.identity) return { ok: false, reason: "identity mismatch" };
  if (payload.caller_type !== expected.callerType) return { ok: false, reason: "caller_type mismatch" };
  if (payload.tool_name !== expected.toolName) return { ok: false, reason: "tool_name mismatch" };
  if ((payload.tool_id ?? undefined) !== (expected.toolId ?? undefined)) return { ok: false, reason: "tool_id mismatch" };

  return { ok: true };
}
