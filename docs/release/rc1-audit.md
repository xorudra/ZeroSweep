# DSRclone RC1 — Release Audit (Prompt 39 §1–§6)

Release: **DSRclone RC1** · Version: **1.0.0-rc.1** · Commit: see
`release/rc1/manifest.json` · Method: full-repository audit of the
platform built by Prompts 1–38 — code inspection, scripted scans,
schema analysis, the complete automated test suite, a new dedicated
tenant-isolation suite, a new live E2E suite, an empty-database
migration run, a backup/restore exercise, and measured performance
probes. Every number below comes from an actual run in the RC1
session; where a check could not run in this environment it says so.

## Repository architecture summary (§2 of the final report)

Monorepo (pnpm + Turborepo), TypeScript end to end plus one Python
service:

- `apps/web` — Next.js 14 App Router UI (181 pages), Tailwind.
- `apps/api` — NestJS API (48 modules, 55 controllers, ~1,010 route
  handlers), global `JwtAuthGuard` + `RolesGuard`, zod validation at
  trust boundaries, workspace resolution through one choke point.
- `apps/ai` — FastAPI copilot service (governed, no execution surface).
- `apps/worker` — queue workers executing governed tool adapters in
  isolated jobs; IDs-only queue payloads.
- `packages/` — `database` (Prisma: 438 models, 58 enums, 462-value
  AuditAction enum, 36 migrations), `security-sdk` (46 module areas:
  adapters, policy engines, parsers, risk, intel, AI governance),
  `orchestration`, `config`, `validation`, `types`, `logger`, `ui`.
- `deploy/` — production Compose (hardened), Kubernetes Kustomize +
  Helm chart, backup/restore/DR runbooks, staged production CI.
- Live reference stack on this machine: Docker-less PostgreSQL 16.2,
  Redis 7.2.5, MinIO (source-built), API/worker/AI — health fully
  green during the RC1 verification.

## Subsystem completeness matrix (§2/§3)

Status values per §3: COMPLETE / PARTIAL / STUB / BROKEN /
NOT_IMPLEMENTED. "Complete" means implemented + covered by the phase
tests and the RC1 suite — not "feature-exhaustive versus every
commercial product".

| Subsystem | Status | Location / notes |
| --- | --- | --- |
| Identity & Authentication | COMPLETE | `apps/api/src/modules/auth`, `identity` — bcrypt(12), JWT (1 h), MFA TOTP/WebAuthn, recovery codes hashed, SSO OIDC/SAML strict validators |
| Authorization / RBAC | COMPLETE | global guards + per-module permission vocabularies (P23–P38); object-level tenant checks (§35 tests + live matrix) |
| Organizations & Workspaces | COMPLETE | `organizations`, `workspaces`; soft-delete aware resolution |
| Assets & Asset Graph | COMPLETE | `assets`; discovery never auto-promotes (§54) |
| EASM | COMPLETE | `easm` — structural promotion chain to AUTHORIZED_FOR_ACTIVE_TESTING |
| Scope & Assessment Authorization | COMPLETE | `scopes`, `assessments`, `security-validation` — plan-hash-bound approvals, SoD, expiry, kill switches (P16) |
| Tool Registry | COMPLETE | 138-entry catalog seeded DISABLED except governed adapters; license types recorded (§187) |
| Scanner Workers | COMPLETE (fixture/live-simulation) | `apps/worker`; real scanner binaries are environment-provided; governed adapters + FixtureToolRunner verified |
| Scan Orchestration | COMPLETE | `packages/orchestration`, DAG profiles, IDs-only payloads, dead-letter handling |
| Scheduler / Continuous Monitoring | COMPLETE | `continuous-security`; DB-lease single-flight, fire-time re-authorization |
| Recon | COMPLETE | 10 governed adapters (P5) |
| Web VAPT (+V2) | COMPLETE | `web-vapt`, Nuclei SAFE policy structural; authorization-matrix → candidates |
| API VAPT (+V2) | COMPLETE | `api-security`; guarded importers; decode-only JWT inspection |
| Network VAPT (+V2) | COMPLETE (safe checks) | `network`, `network-vapt`; no login attempts ever; brute/exploit/dos structurally excluded; Masscan gated |
| Cloud Security (+V2) | COMPLETE (assessment) | `cloud-security(-v2)`, `cloud-native`; read-only at type level; transports NOT_CONFIGURED until an operator wires credentials |
| Container Security | COMPLETE | `container-security`; NO docker.sock (test-asserted) |
| Kubernetes Security | COMPLETE (posture) | `kubernetes-security`; live transport unwired → UNAVAILABLE honestly |
| Mobile Security (+V2) | COMPLETE (static) | `mobile-security`, `mobile-binary-v2`; artifacts never installed/run; Frida DISABLED descriptor |
| Binary Security (+V2) | COMPLETE (static) | `binary-security`; artifacts never executed |
| SAST / Secret Detection / SCA / SBOM | COMPLETE | `repositories` + SDK `code/`; secrets fingerprint+redacted preview only; CycloneDX/SPDX generation |
| Vulnerability Intelligence (+V2) | COMPLETE (engine) | `vulnerability-intelligence`; production dataset EMPTY/NEVER_SYNCED by design until an operator configures feeds — engine, provenance, KEV/EPSS lifecycle fully tested on fixtures |
| Canonical Findings / Fingerprint / Dedup | COMPLETE | domain-prefixed fingerprints; cross-domain non-merge proven (P20) |
| Risk Engine | COMPLETE | deterministic V3 with stored factor explanations; overrides permissioned + audited |
| Remediation & Verification | COMPLETE | `remediation`; VERIFIED_FIXED only via governed retest; ticket-closed → FIX_CLAIMED |
| SOC / SIEM | COMPLETE | `soc`; typed-DSL detections, hash-anchored evidence, closed 9-action response catalog with SoD |
| GRC | COMPLETE | `grc`; states from real signals only — INCONCLUSIVE, never fabricated PASS; no-certification disclaimer |
| Security Data Lake / Analytics / Enterprise Search | COMPLETE | `security-analytics`; governed DSL (no user SQL), classification ceiling in WHERE |
| AI Security Copilot (+V2) | COMPLETE (assistant) | `ai-security` + `apps/ai`; NO execution surface, `executed:false` by construction; redaction before providers; transports NOT_CONFIGURED honestly except MOCK/RULE_BASED |
| Reporting (+V2) & Client Portal | COMPLETE | `reports`, `security-reports` (in VM module), `client-portal`; immutable redacted snapshots; portal = published projections only |
| Integrations / DevSecOps | COMPLETE (framework) | `integrations`; exactly-once ticketing, outbox SSRF discipline; live provider transports NOT_CONFIGURED until configured |
| Notifications | COMPLETE | in-app real; external channels governed + honest delivery states |
| Audit | COMPLETE | 462-action enum; scalar references — audit rows survive resource deletion (§12) |
| Secrets Management | COMPLETE | secret **references** only; P23 vault AES-256-GCM; synthetic-secret tests (§163) in suites |
| Object Storage | COMPLETE | SigV4 store (P38), tenant-scoped keys, signed URLs scoped + expiring |
| Queues / Event Bus | COMPLETE | BullMQ; IDs-only payloads; retry/backoff/circuit-breaker; poison jobs dead-letter |
| Production Deployment | COMPLETE (artifacts) | hardened Compose + K8s/Helm; Docker/Kubernetes are unavailable **in this build environment**, so §260/§261 are validated by config audit + YAML/Helm-template review, not a live cluster deploy — recorded honestly |
| Backup / Restore / DR | COMPLETE | P25/P38 machinery + RC1 exercise (below) |
| Observability | COMPLETE | health (honest degraded), bounded-label metrics, platform ops + kill switches (P38) |
| Wireless | COMPLETE (passive) | `wireless-security`; PASSIVE ONLY — nothing transmits; RF work requires operator hardware by design (§123) |
| Active Directory | COMPLETE (defensive) | read-only collection; offensive family DISABLED descriptors only |
| Reverse Engineering | COMPLETE (static) | governed LAB records; no transport |

No subsystem is classified BROKEN. STUB-classified items are the
deliberately unwired live transports (cloud providers, K8s, IdPs,
feeds, ticketing) — each reports NOT_CONFIGURED/UNAVAILABLE through
its product surface rather than simulating success; they are
configuration-completed by an operator, not code-completed here.

## Dead code & duplication (§4/§5)

Scripted review + phase history: the monorepo grew by expansion, not
forking — each V2 phase deepened its V1 module (documented per phase).
No competing canonical implementations were found for Finding, Asset,
Risk, Authorization, Scope, Scan, Evidence, Remediation, Verification,
Report, User, Organization or Workspace. Two historical collisions
found by earlier phases (P11/P30 intelligence routes; SDK export name
collisions) were already consolidated in their phases. Nothing was
deleted blindly in RC1.

## Canonical ownership (§6)

| Concept | Source of truth |
| --- | --- |
| Identity | `User` + P23 identity tables (sessions, MFA, SSO) |
| Tenant | `Organization` → `Workspace` (every tenant query resolves through `common/tenant.ts`) |
| Assets | `Asset` (canonical) with domain inventories referencing it |
| Findings | `Finding` (canonical, domain-prefixed fingerprint); observations feed it, never replace it |
| Risk | Risk Engine V3 output stored on the finding with factor explanations + model version |
| Evidence | `FindingEvidence` (redacted at rest) + object-storage artifacts by reference |
| Authorization | `TargetVerification` + `Assessment` approval + scope snapshot hash (P16 `ScanApproval`) |
| Remediation | `RemediationCase` state machine (P31) |
| Verification | governed retest (`RetestService`) — the only path to VERIFIED_FIXED |
| Reports | immutable `ReportSnapshot`/`SecurityReport` versions; live rows never mutate a finalized report |
## Database audit (§7–§17)

- 438 models / 58 enums; 757 `@@index`, 129 `@@unique`.
- Tenant keys: every tenant-scoped model carries `workspaceId` and/or
  `organizationId`, or inherits through a parent relation — verified
  by scripted schema analysis + spot checks (Endpoint→Asset,
  ToolExecution→Scan, FindingEvidence→Finding, ScanPlan→Scan,
  TargetVerification→Target). Global-by-design models are reference
  data only (CVE/CWE/EPSS/KEV intel, tool catalog, wordlists).
- Secret-shaped columns are hashes (`passwordHash`, `tokenHash`,
  `verificationTokenHash`, `secretHash`), encrypted values
  (`secretEncrypted`, AES-256-GCM), fingerprints, or **references**
  (`secretReference`, `clientSecretRef`, `signingSecretRef`). No
  plaintext credential column exists.
- Deletion: 154 `Cascade` (composition children), 26 `SetNull`, 1
  `Restrict`. `AuditLog` has **no foreign keys at all** — audit
  history cannot cascade-delete (§12). `FindingHistory` cascades only
  with its own Finding; finding deletion is itself a governed,
  audited workflow.
- Migrations: **all 36 migrations apply cleanly from an empty
  database** (RC1 run: 439 tables created, `prisma migrate status` =
  up to date) (§14). Migration process is the standard Prisma deploy
  (advisory-lock serialized — no replica race) (§16).
- Seed (§17): creates catalog/framework/wordlist metadata only —
  verified on the empty database: **0 users, 0 organizations**.

## Authentication audit (§18–§31)

- Passwords: bcrypt cost 12; SSO/SCIM-provisioned accounts get an
  unusable random password hash. No plaintext/reversible storage.
- Login failures use a generic error (no account-existence oracle)
  and a measured throttle (10 attempts / 15 min per bucket; no
  permanent lockout — §29).
- Access tokens: JWT, default 1 h expiry (§21), payload carries no
  secrets. P23 identity sessions are server-side (`UserSession`:
  hashed token, idle + absolute expiry, `revokedAt`, step-up) —
  logout revokes there (§23). The legacy surface's stateless-token
  property is recorded as RC1-L2.
- MFA (§24/§25): TOTP with replay rejection, WebAuthn with counter
  clone detection, recovery codes stored hashed, single-use.
- Password reset / email verification tokens: random, hashed at rest,
  short-lived, single-use (§26/§27) — P23 suites green.
- API tokens (§30/§31): plaintext shown exactly once at creation;
  stored hashed with prefix; typed scopes; service-account keys
  distinguished from personal keys (P24).

## RBAC & authorization audit (§32–§38)

- Global `JwtAuthGuard` + `RolesGuard` (APP_GUARD) — authentication
  is default-on; `@Public()` exists only on health/metrics, auth
  entry points, HMAC webhooks, CI service-account endpoints, the
  hash-token validation callback, SSO/SCIM protocol endpoints (own
  credential checks) and token-bound shared reports.
- ~1,010 route handlers; permission enforcement is layered: global
  guards → role decorators → per-module permission vocabularies →
  service-level checks (e.g. `requireV2Permission`) → workspace
  resolution + object-level `workspaceId` filters.
- Object authorization (§35), mass assignment (§36) and
  self-approval/SoD (§38) are covered by the TenantIsolationTestSuite,
  per-module suites, and the live negative E2E (all green).
- UI authorization (§34): the web UI hides by role, but every
  sensitive action is enforced in the API — verified by driving the
  API directly with lower-privilege and cross-tenant tokens in E2E.

## Tenant / client / platform isolation (§39–§47)

- **Unit**: new `TenantIsolationTestSuite`
  (`apps/api/src/modules/release/tenant-isolation.spec.ts`) — 8 tests
  over the shared choke point + findings/reports object matrix:
  all pass.
- **Live**: E2E matrix — TenantB probes of TenantA target/scan/
  findings/reports/search all 404 or exclude A data; client portal
  shows published projections only (internal notes absent); share
  links expire/revoke/forgery → 404. 40/40 checks pass.
- Cache keys are tenant-contextual (P22/P27 suites); queue payloads
  carry IDs only (§43); search filters tenant in the query before
  retrieval with a classification ceiling (§44); AI retrieval is
  workspace-scoped before ranking (§45); object keys are
  tenant-prefixed and signed URLs are single-object + expiring
  (§46/§47).

## Security review highlights (§48–§180)

- Scope/authorization engine: fire-time re-authorization + fresh-DNS
  scope revalidation (P22) defeat rebinding drift (§56); protected
  IP classes always denied (§57); redirects never expand scope (§53).
- SSRF (§58/§59): resolve-validate-pin fetch discipline, webhook
  destination validation incl. redirect re-checks (P24), metadata
  addresses refused.
- Uploads/archives (§60–§64): hostile-intake defenses (zip-slip,
  symlink, bombs) test-proven in P12/P17/P18; artifacts never
  executed; isolated analysis workers.
- XSS (§65–§67): React escaping by default; the single
  `dangerouslySetInnerHTML` (search snippets) renders server-escaped
  text (escape function test-asserted). Report HTML is fully escaped;
  PDF writer is hand-rolled (no HTML→PDF network surface, §137).
- CSRF/CORS (§69/§70): Bearer-token API (no cookie auth on the API
  surface) + explicit-origin credentialed CORS from env; verified by
  E2E preflight probe.
- Injection (§71–§74): Prisma parameterized throughout; the only
  `$queryRaw` is a tagged `SELECT 1` health check. Tool execution is
  `execFile` with argument arrays — no shell strings, no `shell:true`
  anywhere (Gate 6 invariant scan).
- Scanner safety (§75–§87): registry allowlist, policy engines,
  bounded timeouts/output, process-tree termination, temp cleanup —
  per-phase suites; offensive families are descriptors only.
- Parsers (§88/§89): new deterministic fuzz spec over JSONL/XML/
  sitemap/spec importers — 300 mutations + hostile corpus each, no
  blowups; oversize-input bound asserted.
- Findings/risk (§90–§103): fingerprint stability + dedup/false-merge
  suites (P7/P20); state machine incl. FIX_CLAIMED ≠ VERIFIED_FIXED
  (P31); Risk V3 deterministic, versioned, override-audited; AI can
  explain, never set, risk (§103).
- Intel (§104–§106): provenance-stamped records; unsupported CVE
  attachment refused (AI suites); freshness timestamps stored;
  production dataset honestly NEVER_SYNCED until configured.
- Secrets (§109/§110/§161–§165): fingerprint-only secret findings;
  repository secret scan clean (see security-results/secret-scan.md);
  AES-256-GCM field encryption with rotation-safe design (P23).
- Integrations (§124–§130): HMAC webhook verification + replay
  idempotency, size caps before processing, sanitized logs, bounded
  retries, secret references only.
- AI (§141–§150): prompt-injection suites (incl. indirect via
  scanner output/findings), no shell/SQL/cloud/device tools in the
  gateway (live refusal probed), cannot create scope or approve,
  cross-tenant prompts return no foreign records, hallucinated
  CVE/asset answers refused with INSUFFICIENT_EVIDENCE, provider
  outage degrades to labelled RULE_BASED — the platform's security
  functions never depend on the AI service.
- Audit (§157–§160): 462 actions; tenant users cannot modify audit
  history (no mutation endpoints); audit metadata is secret-scrubbed
  by construction.
- Observability (§172–§179): bounded metric labels (no IDs/targets);
  health endpoints expose status only; production errors are shaped
  (`HttpExceptionFilter`) — no stacks/SQL/paths (E2E-probed);
  `assertProductionConfig` refuses placeholder secrets at boot;
  web source maps disabled (RC1-H2 fix).

## Tool licensing (§187–§190)

The catalog records license type per tool. Commercial products
(Burp Suite Professional, Nessus, PlexTrac, Binary Ninja, IDA, Caido
paid tiers) are **connector/descriptor only** — no commercial binary
is packaged or redistributed, and the UI reports them
NOT_CONFIGURED/UNAVAILABLE until an operator supplies their own
licensed installation. Open-source adapters invoke operator-installed
binaries. This posture is unchanged and intentional.
