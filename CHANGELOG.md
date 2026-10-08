# Changelog

All notable changes to DSRclone are recorded here. The project follows
semantic versioning; pre-1.0 phase builds (Prompts 1–38) were
development snapshots on the road to RC1.

## [1.0.0-rc.1] — DSRclone RC1 — 2026-10-08

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
