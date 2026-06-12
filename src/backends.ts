// backends.ts — HTTP backend dispatch with signed assertion headers
// Backends are registered at startup via ToolRouter.register().
// Assertion tokens prevent backends from being called without going through the gateway.

export interface BackendConfig {
  type: "http";
  baseUrl: string;
  assertionSecret: string;
  audience: string;
}

export interface LocalBackend {
  type: "local";
  handler: (toolName: string, input: unknown, ctx: InvocationContext) => Promise<unknown>;
}

export type Backend = BackendConfig | LocalBackend;

export interface RouteRule {
  match: RegExp | string;
  backend: Backend;
}

export interface InvocationContext {
  requestId: string;
  identity: string;
  policySetId: string;
  tierId: string;
  callerType: "model" | "code_execution";
}

export class BackendError extends Error {
  constructor(
    message: string,
    public readonly safeMessage: string,
    public readonly statusCode: number,
    public readonly internalDetail?: string,
  ) {
    super(message);
    this.name = "BackendError";
  }
}

async function b64url(buf: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function buildAssertionToken(
  toolName: string,
  ctx: InvocationContext,
  secret: string,
  audience: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({
    sub: ctx.identity,
    aud: audience,
    request_id: ctx.requestId,
    tool_name: toolName,
    tier_id: ctx.tierId,
    iat: now,
    exp: now + 30, // 30s — just enough for the downstream call
  });
  const payloadB64 = await b64url(new TextEncoder().encode(payload).buffer as ArrayBuffer);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${await b64url(sig)}`;
}

async function dispatchHttp(
  toolName: string,
  input: unknown,
  ctx: InvocationContext,
  cfg: BackendConfig,
): Promise<unknown> {
  const assertion = await buildAssertionToken(toolName, ctx, cfg.assertionSecret, cfg.audience);
  const url = `${cfg.baseUrl.replace(/\/$/, "")}/invoke-tool`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Praxis-Assertion": assertion,
        "X-Request-Id": ctx.requestId,
      },
      body: JSON.stringify({ tool_name: toolName, input }),
    });
  } catch (e) {
    throw new BackendError(
      `Backend unreachable: ${e}`,
      "Backend service unavailable",
      503,
      String(e),
    );
  }

  const body = await res.text();
  if (!res.ok) {
    throw new BackendError(
      `Backend returned ${res.status}: ${body}`,
      `Backend error (${res.status})`,
      res.status >= 500 ? 502 : res.status,
      body,
    );
  }
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

export class ToolRouter {
  private rules: RouteRule[] = [];

  register(rule: RouteRule): void {
    this.rules.push(rule);
  }

  async dispatch(
    toolName: string,
    input: unknown,
    ctx: InvocationContext,
  ): Promise<unknown> {
    for (const rule of this.rules) {
      const matches =
        typeof rule.match === "string"
          ? rule.match === toolName
          : rule.match.test(toolName);
      if (!matches) continue;

      const b = rule.backend;
      if (b.type === "local") return b.handler(toolName, input, ctx);
      return dispatchHttp(toolName, input, ctx, b);
    }
    throw new BackendError(
      `No backend registered for tool "${toolName}"`,
      `Tool "${toolName}" has no registered backend`,
      404,
    );
  }
}
