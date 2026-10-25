# ZeroSweep E2E suite (Prompt 39 §198)

Browser/API end-to-end tests for the release candidate. The suite drives
the **live local stack** over HTTP — real API, real worker, real
PostgreSQL/Redis/MinIO — because the properties under test (tenant
isolation, authorization gates, report immutability, AI grounding) are
properties of the integrated system, not of any single module.

## Run

```bash
# stack must be up (see scripts/local-stack/README.md)
API_BASE=http://127.0.0.1:4000/api/v1 \
E2E_RESULTS_PATH=release/rc1/test-results/e2e-results.json \
node tests/e2e/run-e2e.mjs
```

Exit code is non-zero when any check fails. Unit/integration coverage of
the same boundaries (stubbed-Prisma level) lives in the API Jest suites,
including the dedicated `TenantIsolationTestSuite`
(`apps/api/src/modules/release/tenant-isolation.spec.ts`, §39), which the
standard test gate runs on every build. Per-phase live smoke scripts
under `scripts/local-stack/` remain the phase-level regression set and
are all executed for RC1 evidence.

## Fixtures (§199–§209)

Personas and tenants are created fresh per run through the public API:
TenantA (OrgAdmin persona), TenantB (isolation prober), a client
organization with engagement (ClientA surfaces). Targets are fixture
domains (`example.com`, RFC 2606) and scans run only the platform's
simulation adapters — no external system is contacted (§201, §275).
