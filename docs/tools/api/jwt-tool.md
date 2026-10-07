# jwt_tool (JWT inspection)

**Adapter:** `JwtToolAdapter` (`packages/security-sdk/src/api/`),
driven by the platform `JwtInspector`. Deliberately **not** wired
into scan stages as an executable — JWT analysis is a worker platform
stage (`JWT_ANALYSIS`) plus the analyst endpoint
`POST /api/v1/api-security/jwt/inspect`.

## What it does (§23–§25)

Decode-and-observe inspection of tokens obtained legitimately:

- header/claim observations: `alg=none`, missing `exp`, excessive
  lifetime (>24h), sensitive claims present, issuer/audience notes;
- every token is reduced to a SHA-256 **fingerprint** plus a
  **redacted claims summary** (sensitive values become type summaries
  like `string(len=24)` — never the value);
- findings flow through the Phase 7 pipeline with the JWT taxonomy
  classes (`JWT_ALGORITHM_CONFIGURATION`, `JWT_MISSING_EXPIRY`,
  `JWT_EXCESSIVE_LIFETIME`, `JWT_SENSITIVE_CLAIMS`,
  `JWT_ISSUER_AUDIENCE_MISMATCH`) and OWASP API 2023 mapping.

## What it never does

- No signature cracking, no key brute force, no `alg` confusion
  attacks, no token forgery — credential attacks are forbidden by the
  spec's safe posture.
- The raw token is never logged, stored, audited or placed in
  evidence. Token sources are secret REFERENCES (API auth contexts,
  session profiles) resolved only inside the worker boundary; a
  resolved value is inspected only when it is JWT-shaped — other
  secrets are ignored, never recorded.
- Caps: 8 KiB per token, 100 claims, and the discovery budget's
  `maxJwtTokensAnalyzed` per scan.

## Health

HEALTHY by construction (pure platform code) — there is no binary to
be absent.
