# DSRclone RC1 — Release Checklist (§321/§322)

## Product
- [x] Every subsystem from Prompts 1–38 is present (audit inventory, `docs/release/rc1-audit.md`).
- [x] No subsystem classified BROKEN; unwired live transports report NOT_CONFIGURED/UNAVAILABLE honestly.

## Security
- [x] Tenant isolation verified (TenantIsolationTestSuite 8/8 + live §40 matrix in E2E).
- [x] Client isolation verified (portal projection-only, internal notes absent, share-link lifecycle).
- [x] Platform self-security verified (headers, CORS, error shaping, secret scan clean, fuzzed parsers).
- [x] No BLOCKER findings open; HIGH findings fixed (RC1-H2) or explicitly accepted (RC1-H1).
- [x] No real secret in the repository or its history; seed creates no default credentials.

## QA
- [x] Build clean from forced rebuild (11/11 turbo tasks).
- [x] Lint clean (0 errors) and typecheck clean (19/19).
- [x] All tests pass: 2,078 TS + 6 pytest (turbo 15/15 tasks).
- [x] E2E core flow passes live (40/40 incl. negative + AI suites).
- [x] Full live regression passes (13/13 smoke scripts, 270 checks).

## Release
- [x] Version consistent: 1.0.0-rc.1 (packages, API build-info default, Helm chart, manifest).
- [x] Migration verified from an empty database (439 tables; seed = catalog only).
- [x] Backup/restore exercise passed with measured results and identical tenant distribution.
- [x] SBOM (CycloneDX, 617 components) + license inventory generated.
- [x] Release notes, manifest, findings, audit, operations handoff, admin/analyst/client guides published.
- [x] SECURITY.md + CHANGELOG.md added.
- [x] Production CI workflow staged at `deploy/ci/production-ci.yml` (activation needs a `workflow`-scoped token — documented in the file; not forced).
- [x] All 13 release gates PASS (`scripts/release/check-rc1.mjs` → `test-results/release-gates.json`).

## Final status

**RC_READY** — no gate failing.
