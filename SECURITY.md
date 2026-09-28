# Security Policy

Praxis sits on an authorization boundary, so vulnerabilities in authentication, policy resolution, caller verification, quota enforcement, redaction, or backend assertion handling are security-sensitive.

## Supported versions

The `main` branch is the only supported development line until the project begins tagged releases.

## Reporting

Do not open a public issue containing an exploit, credential, token, or private endpoint. Use GitHub's private vulnerability reporting when enabled for the repository. If that is unavailable, contact the maintainer privately through the security contact listed on the maintainer's GitHub profile.

Include the affected commit, a minimal reproduction, expected vs. observed behavior, and the security invariant that failed.

## Threat model

Praxis assumes:

- Worker secrets remain secret.
- Cloudflare account control is outside the Worker threat boundary.
- policy administration is privileged.
- downstream services independently verify `X-Praxis-Assertion`.
- client-supplied identity, trigger, tool name, request ID, and caller metadata are hostile input.

Praxis does **not** currently claim:

- atomic quota accounting under concurrent KV writes;
- durable human-approval state;
- protection from a malicious Cloudflare account administrator;
- arbitrary-regex safety for untrusted policy authors;
- end-to-end authorization if a downstream service ignores its assertion.

## High-value review areas

1. JWT and HMAC verification, expiry and canonicalization.
2. challenge replay and KV consistency.
3. policy fail-closed behavior and override precedence.
4. regex denial-of-service in policy patterns.
5. quota race conditions.
6. redaction bypasses and UTF-8 truncation.
7. backend assertion verification and confused-deputy risks.
