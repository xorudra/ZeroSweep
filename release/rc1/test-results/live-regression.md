# RC1 live regression — full local-stack smoke suite (Prompt 39 §316)

All 13 live smoke scripts under `scripts/local-stack/` were run
against the running RC1 stack (PostgreSQL 16.2 / Redis 7.2.5 / MinIO /
API / worker / AI — health `status: ok` on every dependency) on the
final RC1 build. **13/13 scripts green, 270/270 checks.**

| Script | Result |
| --- | --- |
| smoke.mjs (core register→scan e2e) | 13/13 |
| soc-smoke.mjs | 17/17 |
| easm-smoke.mjs | 20/20 |
| vuln-intel-smoke.mjs | 16/16 |
| remediation-smoke.mjs | 19/19 |
| web-vapt-smoke.mjs | 22/22 |
| network-vapt-smoke.mjs | 27/27 |
| cloud-v2-smoke.mjs | 26/26 |
| mobile-binary-v2-smoke.mjs | 26/26 |
| ai-v2-smoke.mjs | 22/22 |
| reporting-portal-smoke.mjs | 38/38 |
| platform-ops-smoke.mjs | 19/19 |
| minio-smoke.mjs | 5/5 |

Plus the RC1 E2E suite (`tests/e2e/run-e2e.mjs`): **40/40** — see
`e2e-results.json`. Automated totals for RC1: **2,078 TypeScript
tests + 6 pytest**, all passing (turbo 15/15 tasks); build 11/11
tasks (forced, uncached); typecheck 19/19; lint 19/19 (warnings
only, 0 errors).
