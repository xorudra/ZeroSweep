# Architecture overview (Prompt 1 design, as built)

## Service boundaries
- **apps/web (Next.js)** — presentation only. Talks to the API through the typed
  client in `apps/web/src/lib/api-client.ts`. Holds no secrets and makes no
  authorization decisions (UX guards only).
- **apps/api (NestJS)** — the only writer of business state. Owns auth, RBAC,
  organizations/workspaces, targets, verification, scope, assessments, scans
  (records + state transitions), findings, reports, tools registry, integrations,
  credential metadata and audit logs. It **never executes security tools**; it
  creates jobs.
- **apps/worker** — consumes BullMQ jobs, (later phases) resolves trusted tool
  adapters from `packages/security-sdk`, re-checks policy with trusted DB state,
  runs tool containers in isolation, parses/normalizes output and writes results
  back through the API/database boundary.
- **apps/ai (FastAPI)** — consumes **normalized findings only**: explanation, risk
  interpretation, duplicate-correlation assistance, false-positive triage help,
  remediation and summaries. It never launches tools or exploitation. Foundation
  only in this phase; no LLM connected.
- **packages/database** — owns the single Prisma schema and generated client.

## Scan orchestration lifecycle
`QUEUED → PREPARING → RUNNING → (PAUSED) → COMPLETED | PARTIAL | FAILED | CANCELLED`
(state machine enforced in `@dsrclone/types`). Stages: AUTHORIZATION_CHECK →
SCOPE_VALIDATION → PASSIVE_RECON → ASSET_DISCOVERY → DNS_RESOLUTION →
HTTP_DISCOVERY → TECHNOLOGY_DETECTION → PORT_DISCOVERY → CRAWLING →
ENDPOINT_DISCOVERY → PARAMETER_DISCOVERY → SAFE_VULNERABILITY_SCAN →
NORMALIZATION → CORRELATION → RISK_ANALYSIS → REPORT_GENERATION. Later-stage
tools consume artifacts produced by earlier stages.

## Tool-adapter architecture
Every tool implements the `SecurityToolAdapter` contract (`packages/security-sdk`):
metadata (category, risk level, capabilities, supported target types, license,
approval), validateConfiguration/Target/Scope, checkAvailability, prepare,
buildExecutionPlan (executable + validated argument array — never a shell
string), execute, parse, normalize, cleanup, healthCheck. The orchestration
engine selects tools by **capability and target type**, never by hardcoding.

## Isolated workers
One job = one isolated container per tool execution with CPU/memory/PID/time
limits, read-only root filesystem where possible, no privileged mode, no host
networking, no Docker socket, network policy (NO_NETWORK / TARGET_ONLY /
SCOPE_ONLY / INTERNET_READ_ONLY / CUSTOM_ALLOWLIST) enforced against the
authorized scope, output-size caps, and DNS re-validation at execution time
(rebinding protection). Secrets are resolved by reference inside the worker
boundary only.
