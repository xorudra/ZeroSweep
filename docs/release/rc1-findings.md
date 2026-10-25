# ZeroSweep RC1 — Release Findings (Prompt 39 §278–§284)

Severity scale (§279): BLOCKER / CRITICAL / HIGH / MEDIUM / LOW / INFO.
Policy: every BLOCKER fixed before RC (§281); every CRITICAL fixed or
the release must not be called production-ready (§282); every HIGH has
an explicit release decision (§283); every fixed defect has a
regression test (§284).

## Findings register

| ID | Severity | Title | Status | Disposition |
| --- | --- | --- | --- | --- |
| RC1-M1 | MEDIUM | Client-portal admin API returned HTTP 500 on malformed bodies (unguarded `input.slug.toLowerCase()` in `createClient`; same pattern in `createEngagement`) | FIXED | Controller now validates all admin POST bodies with zod/`parseOrThrow` (standard §227 error shape); service re-checks required fields defensively. Regression: `apps/api/src/modules/client-portal/client-portal.controller.spec.ts` (4 tests) + live E2E check "malformed admin body is a 400, never a 500". Found by the RC1 E2E suite against the live stack. |
| RC1-H1 | HIGH | Dependency advisories in Next.js 14.2.35's vendored postcss (<8.5.10, CSS stringify XSS) and optional sharp (memory exhaustion) — `pnpm audit`: 22 advisories total, 0 critical, 9 high, 10 moderate, 3 low/info | ACCEPTED for RC1 (explicit §283 decision) | Exposure analysis: postcss runs at **build time on the platform's own stylesheets only** — no untrusted CSS is ever processed; sharp is an optional Next dependency used for image optimization of platform assets, not attacker-supplied images (uploads are never transcoded by Next). The vulnerable code is vendored inside Next and cannot be patched via pnpm overrides; the upstream fix requires the Next 15/16 migration (React 19), which is a post-RC1 upgrade train item (see rc1-audit.md known issues). Residual runtime risk assessed LOW. All other flagged chains (qs 6.14.2 ≥ patched 6.14.1; body-parser; markdown ReDoS chain in dev/docs tooling; jws installed copies are 3.2.3 / 4.0.1, the patched releases) are moderate/low with no reachable untrusted-input path in production flows. |
| RC1-H2 | HIGH | Web UI served no Content-Security-Policy or related security headers (only the API had helmet) | FIXED | `apps/web/next.config.mjs` now serves CSP + X-Content-Type-Options + X-Frame-Options DENY + Referrer-Policy + Permissions-Policy on all routes, and pins `productionBrowserSourceMaps: false` (§180). Verified live against the production build (headers captured in RC1 verification). Gate 12 now asserts the CSP is present in config. |
| RC1-M2 | MEDIUM | `GET /vulnerabilities` list latency is materially higher than sibling list endpoints (measured mean 357 ms / p95 435 ms at pageSize=50 over a 5,000-finding workspace, vs 65 ms for `/findings`) — per-row intelligence enrichment pattern | ACCEPTED for RC1 | Bounded by enforced pagination (pageSize ≤ 200 everywhere sampled); no correctness or isolation impact. Recorded with measurements in `release/rc1/performance-results/`; optimization (batched enrichment) is a post-RC1 performance item. |
| RC1-L1 | LOW | `DeadLetterJob` carries no tenant key and no FK — tenant attribution is indirect via `scanId` | ACCEPTED (by design) | Dead-letter records are platform-operational data surfaced only through the platform-ops admin surface (P38); payloads are IDs-only, so no tenant content is stored. Documented in rc1-audit.md §7. |
| RC1-L2 | LOW | Legacy `/auth` surface issues stateless JWT access tokens (1 h default expiry) that cannot be server-side revoked on logout; the P23 identity surface has full server-side sessions (`UserSession` with hashed tokens, revocation, idle/absolute expiry) | ACCEPTED (documented design) | Short expiry + bcrypt(12) + login throttling bound the window. Operators requiring revocable sessions should front the identity surface. Recorded so the property is explicit, not discovered. |
| RC1-L3 | LOW | Prometheus `/metrics` endpoint is unauthenticated at the application layer | ACCEPTED (by design) | Documented in-code: deployments restrict it via NetworkPolicy to the monitoring namespace; it exposes only bounded-label counters (no tenant IDs, no secrets — §173/§174 verified in P25/P38). Operators must not expose it publicly; called out in the operations handoff. |
| RC1-I1 | INFO | Test fixtures contain the canonical AWS **documentation** example keys (`AKIAIOSFODNN7EXAMPLE`, the AWS docs secret example) and synthetic fake secrets | ACCEPTED (by design) | These are AWS's published documentation examples used as planted canaries; dozens of tests assert they never reach outputs, logs, reports or AI context. The RC1 secret scan (Gate 10) allowlists these exact values; anything else matching a secret pattern fails the gate. |
| RC1-I2 | INFO | `pnpm audit` endpoint intermittently returns HTTP 403 from this environment's registry proxy after the first successful run | NOTED | The successful run's full results are recorded in `release/rc1/security-results/dependency-audit.md`. Re-run the audit in CI (staged workflow) where the endpoint is reachable. |

## BLOCKER findings

None. No cross-tenant access, authentication/authorization bypass,
arbitrary command execution, plaintext production secret, broken
backup/restore, unsafe production default, or data-corruption defect
was found by the RC1 audit; the tenant-isolation suite (unit +
live §40 matrix), authorization suites and negative E2E all pass.

## CRITICAL findings

None open. (RC1-H1/RC1-H2 were the highest-severity items; H2 is
fixed, H1 carries the explicit §283 acceptance above.)
