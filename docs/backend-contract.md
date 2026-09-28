# Backend assertion contract

A Praxis backend is a deliberately small HTTP adapter. It receives an already policy-approved invocation and must still authenticate Praxis itself.

## Request

```http
POST /invoke-tool
X-Praxis-Assertion: <payload>.<signature>
X-Request-Id: 6c86...
Content-Type: application/json
```

```json
{
  "tool_name": "search_repositories",
  "input": {}
}
```

The assertion payload is base64url-encoded JSON and the signature is HMAC-SHA256 over that encoded payload.

```json
{
  "sub": "daedalus",
  "aud": "github-mcp-gateway",
  "request_id": "6c86...",
  "tool_name": "search_repositories",
  "tier_id": "T1_READONLY",
  "iat": 1790550000,
  "exp": 1790550030
}
```

## Backend verification

A conforming adapter MUST:

1. split the token into exactly two components;
2. verify HMAC-SHA256 using the backend-specific shared secret;
3. reject expired assertions and implausibly future `iat` values;
4. require the configured `aud`;
5. require `X-Request-Id === payload.request_id`;
6. require the JSON body's `tool_name === payload.tool_name`;
7. authorize the asserted identity for the backend if it has its own ACL;
8. avoid forwarding the assertion to unrelated upstream services.

The backend SHOULD log request ID, identity, tool, tier and decision outcome, but MUST NOT log the shared secret or raw authorization credentials.

## Response

Success may be JSON or text. Praxis normalizes either form to text before applying response-byte accounting and policy redaction.

Non-2xx responses are converted to a safe gateway error. Sensitive backend details should therefore remain in backend logs rather than response bodies.

## Integration sequence

The safest first adapters are read-only:

1. expose one backend adapter route;
2. verify assertions;
3. map a very small set of read tools;
4. add contract tests for bad signature/audience/expiry/request ID/tool;
5. only then add the route to a Praxis policy tier.

Writes should be introduced separately, with idempotency and approval semantics explicit.
