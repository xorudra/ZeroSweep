# DSRclone — Authorized Automated VAPT Platform

DSRclone is a **GUI-first** automated VAPT (Vulnerability Assessment & Penetration
Testing) and security-assessment orchestration platform. An authorized user registers
a target, **verifies ownership**, defines **scope**, chooses an assessment profile,
and DSRclone orchestrates security tools through standard adapters, normalizes and
deduplicates their findings, scores risk, and generates professional reports.

The user never touches a command line: every workflow is clicks, forms and buttons.
Security tools run only inside isolated workers — never in the web server, and never
without verified scope and approval.

> **Status — Phase 8 complete (Prompts 1–8).** Production monorepo, backend and
> database foundation, the complete Tool Adapter SDK, a 126-tool metadata
> catalog, the scan orchestration engine, ten reconnaissance adapters, the
> web attack-surface discovery engine (ffuf, Feroxbuster, Gobuster dir-mode
> only, Wfuzz controlled-templates only, Arjun), the first findings pipeline
> (Nuclei under a governed SAFE template policy, Nikto, testssl.sh, SSLyze)
> with canonical-fingerprint correlation and a deterministic risk engine —
> and now the **interactive proxy-scanner layer**: OWASP ZAP, Burp Suite
> Professional and Caido as API-driven connectors with isolated
> per-assessment contexts, SSRF-safe endpoint references (never
> client-supplied URLs), passive analysis, traffic/endpoint/issue import,
> evidence redaction, and approval-gated active scanning (intrusive,
> disabled by default). Burp and Caido are commercial/external products by
> design: their connectors report NOT_CONFIGURED until an instance is
> registered in-product, which is a product state, not an error. Everything
> runs only inside approved scans against verified, in-scope targets.
> Adapters whose binaries are absent report UNAVAILABLE honestly and
> pipelines degrade — nothing fakes a real run. The AI service has no LLM
> connected yet.

## Architecture

```
Web UI (Next.js) ──> API Gateway / Backend (NestJS, /api/v1)
                        │
                        ├─ Authorization & Scope Service
                        ├─ Assessment Service ──> Job Queue (BullMQ / Redis)
                        │                              │
                        │                              v
                        │                     Security Workers (isolated)
                        │                              │  Tool Adapters (SDK)
                        │                              v
                        │                     Parser / Normalizer ─> Correlation/Dedup
                        │                              │
                        ├─ Risk Engine <───────────────┘
                        ├─ AI Analysis Service (FastAPI — normalized findings only)
                        └─ Reporting Engine
Supporting: PostgreSQL · Redis · MinIO (S3) · Audit · Notifications · Scheduler · Secrets references
```

See `docs/architecture/` for service boundaries, database ownership, queue
architecture, object storage, authorization boundaries and the GUI page map.

## Safety architecture (non-negotiable)

- Every intrusive assessment requires **explicit authorization**: target ownership
  verification (DNS TXT / HTTP file / manual approval), scope, and approvals.
- Scope can never silently expand beyond what was verified.
- Default scans are non-destructive. Destructive, exploitative, credential-based,
  brute-force, persistence or lateral-movement capabilities **never** run merely
  because a URL was entered — they need an isolated lab / separately approved profile
  and are disabled by default in the policy engine (`packages/security-sdk`).
- Internal, loopback, link-local and cloud-metadata targets are blocked unless an
  internal engagement is explicitly approved (SSRF protection).
- There is **no API that accepts a raw command**. Users submit assessments; workers
  resolve trusted adapters internally.
- Credentials are stored as **metadata + secret references only** — never plaintext.

## Monorepo structure

```
dsrclone/
├── apps/
│   ├── web/        Next.js dashboard (GUI)
│   ├── api/        NestJS API (/api/v1) — never executes tools
│   ├── ai/         FastAPI AI service (foundation; no LLM yet)
│   └── worker/     BullMQ worker foundation (placeholder job only)
├── packages/
│   ├── database/       Prisma schema + client (single source of truth)
│   ├── types/          Shared types + scan state machine
│   ├── validation/     Zod schemas (target, scope, assessment, scan, pagination)
│   ├── security-sdk/   Tool adapter SDK: metadata, policy engine, scope matcher, mock adapter
│   ├── logger/         Structured logging with secret redaction
│   ├── config/         Shared env schema + constants
│   └── ui/             Shared UI components
├── infrastructure/  Docker, Postgres, Redis, MinIO, worker notes
├── docs/architecture/
├── docker-compose.yml
├── pnpm-workspace.yaml
└── turbo.json
```

## Prerequisites

- Node.js ≥ 20 and pnpm 9 (`npm i -g pnpm@9` or corepack)
- Docker + Docker Compose (for PostgreSQL / Redis / MinIO)
- Python 3.11+ (for `apps/ai`)

## Setup

```bash
cp .env.example .env          # local values only — never commit .env
pnpm install
docker compose up -d postgres redis minio minio-init
pnpm db:generate              # Prisma client
pnpm db:migrate               # apply migrations to the local database
pnpm db:seed                  # tool catalog metadata (no commands, nothing executed)
```

## Development commands

```bash
pnpm dev          # all apps (turbo)
pnpm build        # build everything
pnpm lint
pnpm typecheck
pnpm test         # TS test suites (validation, scope/policy, RBAC, state machine, API)
pnpm test:ai      # Python tests for apps/ai
```

Run one app: `pnpm --filter @dsrclone/web dev` (port 3000),
`pnpm --filter @dsrclone/api dev` (port 4000), `pnpm --filter @dsrclone/worker dev`,
`cd apps/ai && uvicorn app.main:app --port 8000`.

Health checks: API `GET /api/v1/health` (API/Postgres/Redis/MinIO/AI), AI `GET /health`,
worker heartbeat file + structured logs.

## API (versioned, /api/v1)

`auth` (register/login/me) · `users` · `organizations` · `workspaces` · `targets`
(+ `/verifications`) · `scopes` · `assessments` (+ `/approve`) · `scans` (+ `/cancel`) ·
`findings` · `reports` · `tools` (+ `/categories`, `/capabilities`, `/:id/health`) ·
`integrations` · `credentials` (metadata only) · `audit-logs` · `notifications` · `health`.

There is deliberately **no** execute/command endpoint.

## Testing

Unit/integration tests cover: target & scope validation, the scope matcher and
policy engine (incl. cross-organization denial), RBAC guards, organization
isolation, scan state transitions, API validation and health, the mock adapter,
and the AI health endpoint.

## Roadmap (from the master spec)

1. ✅ Architecture (Prompt 1) 2. ✅ Monorepo + backend + database foundation (Prompt 2)
3. ✅ Universal Tool Adapter SDK, registry & safe execution framework (Prompt 3)
4. ✅ Production scan orchestration engine, DAG pipeline, queue workers & live progress (Prompt 4)
5. ✅ First real adapters: reconnaissance, asset discovery & web surface mapping (Prompt 5)
6. ✅ Web attack-surface, content, route & parameter discovery engine (Prompt 6)
7. ✅ Safe vulnerability detection, TLS analysis, normalization, correlation & risk engine (Prompt 7)
8. ✅ OWASP ZAP, Burp Suite & Caido integration layer (Prompt 8)
9. API security testing 10. Network VAPT 11. Reporting engine
12. API/cloud/container/source-code modules 13. Lab-only modules (AD, wireless, mobile)

## Changelog

- **2026-10-07 — Prompt 8: OWASP ZAP, Burp Suite & Caido Integration.** A
  dedicated `InteractiveScannerConnector` abstraction beside the CLI
  adapters (connect, per-assessment contexts, scope configuration,
  session authentication, endpoint/traffic import, passive analysis,
  issue import, policy-gated active scan, guaranteed cleanup), adapted
  into the standard adapter lifecycle so orchestration, budgets and
  result processing treat connectors like every other tool. ZAP is
  API-driven with context include/exclude rules derived from the approved
  scope; Burp Suite Professional is an ADMIN_PROVIDED connector that
  imports Burp's documented XML issue export (directly or through a
  small admin-run bridge inside the licensed environment — no invented
  APIs, license state read from the deployment); Caido detects
  capabilities from the connected instance and degrades honestly.
  Scanner instances are registered by administrators using opaque
  endpoint REFERENCES resolved only from server configuration —
  client-supplied scanner URLs are rejected by design (SSRF-safe).
  Credentials are secret references resolved only in trusted boundaries.
  New PASSIVE_SECURITY_ANALYSIS stage (skips honestly, never simulated,
  when nothing is configured); ACTIVE_SECURITY_ANALYSIS exists in the
  stage library only, behind verified-target + approved-assessment +
  expiring scope-hash-bound approval + budget gates, prepared but not
  enabled. Imported issues flow through the same Phase 7
  normalization/correlation/risk pipeline with explicit per-product
  severity/confidence mapping tables; HTTP transactions persist as
  metadata + SHA-256 hashes + object-storage references with redacted
  display copies; manual imports (ZAP JSON, Burp XML, Caido JSON, HAR)
  are format/size/XXE-guarded; raw-evidence access is Owner/Admin and
  audit-logged. GUI: Settings → Scanner Instances, per-tool connector
  panels, live passive-analysis progress, scan HTTP-history page.
  Verified entirely against recorded fixtures/mocks — no connector was
  run against any real target. See `docs/tools/proxy/`,
  `docs/architecture/proxy-scanner-connectors.md`,
  `docs/security/authenticated-scanning.md` and
  `docs/security/active-scan-approval.md`.
- **2026-10-07 — Prompt 7: Safe Vulnerability Detection & TLS Analysis.**
  First findings adapters: Nuclei under a governed SAFE template policy
  (INTRUSIVE/DISABLED templates can never be selected), Nikto with
  classified promotion (unclassifiable output stays INFORMATIONAL),
  testssl.sh and SSLyze for TLS services. Canonical-fingerprint
  correlation merges the same issue across tools with all evidence
  preserved and sources unioned; a deterministic risk engine scores
  findings with stored explanations; Findings API + GUI with review
  workflow and history. Verified against recorded fixtures only.
- **2026-10-07 — Prompt 6: Web Attack-Surface, Content, Route & Parameter
  Discovery Engine.** Five production adapters in the security-sdk (ffuf,
  Feroxbuster, Gobuster dir-mode-only, Wfuzz controlled-templates-only,
  Arjun) with dedicated parsers and honest health. Governed wordlists:
  bundled starter lists with checksums in controlled storage, admin-managed
  references in a new `Wordlist` table, selection by registered id or
  profile (SMALL/STANDARD/COMPREHENSIVE — never auto-comprehensive, never a
  filesystem path). Truthful inventory: response fingerprints, soft-404
  calibration, wildcard-route collapse, redirect recording without
  following, API/SENSITIVE_ROUTE classification (labels, not findings),
  crawler-trap guards, and `EndpointParameter`/`EndpointForm` inventory —
  parameter NAMES and form structure only, values never stored. Pipeline:
  new CONTENT_DISCOVERY + WEB_SURFACE_NORMALIZATION stages (WEB_BASELINE =
  one adapter + SMALL lists; WEB_COMPREHENSIVE/API_ASSESSMENT = standard
  content + parameter discovery), worker-derived wordlist profiles and
  Wfuzz templates, per-stage PARTIAL degradation when one tool fails. APIs
  (`/endpoints/:id`, `/endpoints/:id/parameters`, `/assets/:id/web-surface`,
  `/scans/:id/web-surface`) and GUI (Web Surface page, endpoint detail,
  enriched endpoint table, asset/scan panels). Everything verified against
  recorded fixture outputs of a controlled test application — no tool was
  run against any real target. See
  `docs/architecture/web-surface-discovery.md` and
  `docs/tools/web-discovery/`.
- **2026-10-07 — Prompt 5: Real Reconnaissance Adapters.** Ten production
  adapters in the security-sdk (Subfinder, Amass, Assetfinder, Findomain,
  dnsx, httpx, WhatWeb, gau, Waybackurls, Katana) with argument-array-only
  execution plans, dedicated parsers, and honest health (real `--version`
  when a binary exists, UNAVAILABLE when it does not). Pipeline: multi-adapter
  stages, per-adapter executions, stage inputs chained from persisted
  in-scope inventory, scope verdicts on every discovered asset/URL, wildcard
  DNS probe, discovery budgets, sensitive-parameter redaction, raw artifacts
  per tool in object storage. Inventory APIs (`/assets`, `/assets/:id`,
  `/endpoints`, `/scans/:id/recon-summary`, …) and GUI (Assets, asset detail,
  Endpoints, Live Scan recon summary, live tool health). Everything verified
  against recorded fixture outputs — no tool was run against any real target.
  See `docs/architecture/recon-pipeline.md` and `docs/tools/recon/`.
- **2026-10-07 — Prompt 4: Scan Orchestration Engine.** New
  `@dsrclone/orchestration` package (stage/execution state machines, profile
  templates, DAG builder+validator, tool selection, authorization/scope
  gates, weighted progress, durable event contract, idempotency/retry,
  concurrency limits, worker recovery). API orchestration module (plan
  preview, start scan, scan details, events + tenant-isolated SSE stream,
  pause/resume/cancel/emergency-stop, admin operations). Worker rebuilt as a
  DAG runner + stage executor over Prisma with WorkerNode registration/
  heartbeat, startup recovery and graceful draining; migration adds
  ScanPlan/ScanEvent/WorkerNode/DeadLetterJob. Live Scan page at `/scans/[id]`
  with DAG view, timeline and controls. Mock E2E (PASSIVE_RECON + WEB_BASELINE)
  completes end-to-end in tests; still no real scanner anywhere. See
  `docs/architecture/orchestration-engine.md` and
  `docs/operations/worker-lifecycle.md`.
- **2026-10-07 — Prompt 3: Tool Adapter SDK.** Completed `packages/security-sdk`
  (adapter lifecycle + base gates, registry with metadata validation, policy
  engine with all reason codes, target/scope validation with SSRF + DNS-rebinding
  guards, JSON/JSONL/XML parsers, output/timeout/rate limits, container contract,
  Local Echo test adapter), expanded the seeded tool catalog to 126 tools across
  all 13 categories (metadata only, catalog adapters disabled), added tool list
  filters to the API, and built the filterable Tools page + tool detail view.
  See `docs/architecture/tool-adapter-sdk.md`.
- **2026-10-07 — v0.1.0 foundation.** New pnpm/Turborepo monorepo supersedes the
  earlier standalone scaffold (Flask backend + React/Vite frontend), which was
  removed; this codebase is the single DSRclone going forward.
