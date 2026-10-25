# Changelog

All notable changes to ZeroSweep are recorded here. The project follows
semantic versioning; pre-1.0 phase builds (Prompts 1–38) were
development snapshots on the road to RC1.

## [1.0.0] — ZeroSweep v1.0 — 2026-10-08

Prompts 1–40 complete. The RC1 baseline (0 BLOCKER / 0 CRITICAL open)
plus SaaS productization and launch preparation (Prompt 40).

### Added
- Productization module (`apps/api/src/modules/product/`): product
  modes, versioned plans + entitlements with the §15 precedence chain
  and fail-closed backend gating (safety invariants can never be
  entitled away), subscriptions with upgrade/downgrade-impact flows,
  trials, provider-abstracted billing (signed, replay-protected,
  idempotent webhooks; card data refused; never simulated when
  unconfigured), Ed25519 product licensing (public-key verification
  only, grace + revocation), idempotent real-row usage metering,
  race-safe quota reservations with structured QUOTA_EXCEEDED
  responses, platform-only quota overrides.
- Transactional signup/provisioning, single-use email verification,
  10-step security-first onboarding with authorization attestation,
  organization lifecycle (retention, deletion preview, legal hold),
  abuse prevention with protected-target blocking, effective
  capability resolution, redacted support diagnostics, upgrade
  preflight.
- Platform control plane (`/platform/*` product routes): metadata-only
  organization views, plans/subscriptions/licenses/usage/trials/
  features/release, and reason-bound, tenant-approved, expiring,
  audited support access sessions.
- Scan-start product gate in orchestration (demo orgs, lifecycle,
  protected targets, entitlements, quotas) layered AFTER the P38
  platform kill switches and never weakening the authorization gates.
- Web: /settings/usage, /settings/plan, /settings/billing,
  /settings/license, /onboarding, /admin/product, /status and
  labelled DRAFT legal placeholders.
- SDK product module (`packages/security-sdk/src/product/`) with the
  feature registry, license crypto, billing webhook verification,
  quota/lifecycle/launch-gate pure logic — 36 tests; API product
  battery — 26 tests.
- Docs: docs/product/*, docs/getting-started/*, user/admin guides,
  API docs, operations runbooks; generated tool docs
  (`docs/tools/`); config/product.example.env; safe installer
  (scripts/install/install.sh); launch gate evaluator
  (scripts/product/launch-gates.mjs); release/v1.0 artifacts.

### Notes
- Versions advanced 1.0.0-rc.1 → 1.0.0 across the release train.
- No repository LICENSE file is added: the project's legal terms are
  the owner's decision (the product's own licensing machinery is the
  Prompt 40 feature above).

## [1.0.0-rc.1] — ZeroSweep RC1 — 2026-10-08

First release candidate. Prompts 1–38 audited, hardened, verified
end-to-end and frozen (Prompt 39).

### Added
- TenantIsolationTestSuite (unit) and a live E2E suite (`tests/e2e/`)
  covering the complete governed flow, the §40 tenant-isolation
  matrix, client isolation, negative cases, self-security probes and
  AI grounding checks.
- Parser fuzzing suite for scanner/importer parsers (§88).
- Release gate script `scripts/release/check-rc1.mjs` (13 mandatory
  gates) and release SBOM/license generation
  `scripts/release/generate-sbom.mjs`.
- Release artifacts under `release/rc1/` (manifest, notes, checklist,
  test/security/performance/DR results) and audit documents under
  `docs/release/`.
- Web UI security headers + CSP (`apps/web/next.config.mjs`).

### Fixed
- Client-portal admin API no longer returns HTTP 500 on malformed
  request bodies; all admin POST bodies validate with the standard
  zod contract (RC1-M1, with regression tests).

### Security
- Full-platform audit: authentication/session/MFA, RBAC, tenant and
  client isolation, SSRF/upload/XSS/CSRF/CORS, SQL/command
  injection, scanner safety, secrets handling, AI security — see
  `docs/release/rc1-audit.md` and `docs/release/rc1-findings.md`.
- Dependency audit recorded (0 critical; the Next.js vendored-postcss
  HIGH is dispositioned as RC1-H1 with an explicit acceptance and a
  scheduled framework upgrade).

### Release identity
- Version aligned to `1.0.0-rc.1` across package metadata, API build
  info default, Helm chart and release manifest (§302).

## [0.1.0] — Prompts 1–38 (development)

Platform built phase by phase: foundation, tool-adapter SDK and
registry, orchestration, recon, web/API/network VAPT, vulnerability
management and intelligence, source/container/cloud/AD/mobile/binary/
wireless engines, controlled validation, unified reporting, AI
copilot, continuous monitoring, enterprise identity (SSO/MFA/SCIM),
integrations, deployment/HA/DR, GRC, data lake, SOC, EASM, and the
V2 deepening phases 32–38. Per-phase detail lives in the git history
and `docs/`.
