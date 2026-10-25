<img src="apps/web/public/zerosweep-logo.png" width="120" alt="ZeroSweep logo">

# ZeroSweep — Authorized Automated VAPT Platform

ZeroSweep is a **GUI-first** automated VAPT (Vulnerability Assessment & Penetration
Testing) and security-assessment orchestration platform. An authorized user registers
a target, **verifies ownership**, defines **scope**, chooses an assessment profile,
and ZeroSweep orchestrates security tools through governed adapters, normalizes and
deduplicates their findings, scores risk, and generates professional reports.

The user never touches a command line: every workflow is clicks, forms and buttons.
Security tools run only inside isolated workers — never in the web server, and never
without verified scope and approval.

## 🧊 3D Architecture

An authorized user comes in through Caddy to the Next.js console. The NestJS API checks scope and approval at the safety gate; only then do isolated Docker workers run the tools — Postgres on Neon holds state, Redis queues the work, Supabase stores the artifacts, and the AI copilot answers through Nexus.

**Interactive:** open [`docs/3d/index.html`](docs/3d/index.html) in a browser — drag to orbit, scroll to zoom.


## Status at a glance

- **Build complete** — all 40 phases of the master spec implemented (see the
  [phase map](#phase-map) below).
- **Tests** — 2,140 TypeScript tests + 6 Python tests passing; full live regression
  296/296 checks across the committed smoke scripts.
- **Release status** — `V1_READY` per the Phase 40 launch gates; release-candidate
  audit: 0 blocker / 0 critical open (report in `docs/release/`).
- **Live demo** — live on Oracle Cloud as one merged deployment, monitored
  by UptimeRobot (next section).
- **Console** — searchable sidebar navigation, a platform **Admin Panel**
  (aggregate stats plus a live status list of every service), and a user
  profile page. Web console, API, AI copilot and worker run together
  behind one front door.

## Live deployment

Since 2026-10-12 the whole platform runs as **one merged deployment** on an
Oracle Cloud free-tier server (the four separate Render services were
retired after Render's free instance hours ran out): web console, API, AI
copilot service, worker and Redis live in a single container behind one
address, and sign-up is invite-only.

> Temporary address while the zerosweep domain name is being set up —
> the links below use the server's IP-based URL and will move to
> zerosweep.duckdns.org once that name is ready.

| Piece | URL |
|---|---|
| Web console | https://130-210-56-74.sslip.io |
| API health | https://130-210-56-74.sslip.io/api/v1/health/live |
| AI copilot service health | https://130-210-56-74.sslip.io/ai/health |
| Worker health | https://130-210-56-74.sslip.io/worker-health |
| Database / storage | Neon Postgres 16 (free plan) + private Supabase Storage bucket |

Verified live 2026-10-12: API health reports **all checks ok** (api /
postgres / redis / object storage / ai), the AI copilot is connected to
the Nexus /v1 API, and invite-only registration refuses public sign-ups
(403). The server runs 24×7 — no idle spin-down. For a real production
topology (HA, DR, observability), see `deploy/` instead — this deployment
is the public demo, not that path.

Uptime is monitored by UptimeRobot (free): **ZeroSweep Web**, **ZeroSweep API**
(`/api/v1/health/live`), **ZeroSweep AI** (`/ai/health`) and **ZeroSweep Worker**
(`/worker-health`), each checked every 5 minutes with downtime alerts by email.

## What it does

- **Assessment domains** — recon & asset discovery, web attack-surface discovery,
  safe vulnerability detection & TLS analysis, API security, network VAPT,
  source-code security (SAST / secrets / SCA), container & Kubernetes security,
  multi-cloud posture, Active Directory assessment, controlled pentest validation,
  mobile & binary analysis, wireless (passive only), and external attack-surface
  management (EASM).
- **Tool layer** — a 129-tool metadata catalog behind a Tool Adapter SDK with a
  policy engine: every tool is classified, governed, and run only through trusted
  adapters. Commercial scanners (Burp Suite Professional, Caido) are API-driven
  connectors that report `NOT_CONFIGURED` until an instance is registered —
  a product state, not an error.
- **Findings pipeline** — parsers normalize tool output into canonical findings;
  fingerprint correlation deduplicates across tools; a deterministic risk engine
  scores with CVSS / CVE / CWE / OWASP / EPSS / KEV context. Candidates are never
  presented as confirmed findings.
- **Vulnerability management** — lifecycle, remediation orchestration with SLAs,
  fix verification through governed retests, exceptions with expiry, and
  regression detection.
- **AI copilot** — grounded analysis over *normalized findings only*: explanation,
  remediation drafting, summaries, and a governed planning layer. The AI never
  launches scans or exploitation, never executes tools, and refuses secret-shaped
  data. A live LLM is connected (2026-10-09): the service takes any
  OpenAI-compatible endpoint via `AI_LLM_*` env vars and is supplied by
  Nexus Local's key-gated `/v1` API (model `nexus-auto`, which fails over
  across Nexus's provider lanes). With no endpoint configured it reports
  `NOT_CONFIGURED` honestly and answers via the deterministic mock.
- **Enterprise platform** — SSO / MFA / SCIM, compliance & GRC, a security data
  lake with governed search, SOC / SIEM detection and incident response,
  integrations & DevSecOps hooks, a client portal, and SaaS productization
  (plans, entitlements, signed product licenses).

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
- A scan is refused unless the target is **VERIFIED** and the assessment is
  **APPROVED**. Discovered assets never expand scope.
- Scope can never silently expand beyond what was verified.
- Default scans are non-destructive. Destructive, exploitative, credential-based,
  brute-force, persistence or lateral-movement capabilities **never** run merely
  because a URL was entered — they are excluded in the policy engine
  (`packages/security-sdk`) and stay disabled by default.
- Internal, loopback, link-local and cloud-metadata targets are blocked unless an
  internal engagement is explicitly approved (SSRF protection).
- There is **no API that accepts a raw command**. Users submit assessments; workers
  resolve trusted adapters internally.
- Credentials are stored as **metadata + secret references only** — never plaintext.
- **No fake findings, ever.** Demo or fixture data is always labelled as such, and
  every phase was verified fixture-only (recorded outputs, `example.com`,
  RFC 5737 documentation ranges) — no tool was ever run against a real target
  during the build.

## Monorepo structure

```
zerosweep/
├── apps/
│   ├── web/        Next.js dashboard (GUI)
│   ├── api/        NestJS API (/api/v1) — never executes tools
│   ├── ai/         FastAPI AI copilot service (normalized findings only)
│   └── worker/     BullMQ workers — scan execution, reporting, schedulers
├── packages/
│   ├── database/       Prisma schema + client (single source of truth)
│   ├── types/          Shared types + scan state machine
│   ├── validation/     Zod schemas (target, scope, assessment, scan, pagination)
│   ├── security-sdk/   Tool adapter SDK: metadata, policy engine, scope matcher
│   ├── logger/         Structured logging with secret redaction
│   ├── config/         Shared env schema + constants
│   └── ui/             Shared UI components
├── deploy/         Production assets: Dockerfiles, Compose, Helm, CI, runbooks
├── docs/           Architecture, operations, release and product documentation
├── scripts/        Local-stack and Render helper scripts
├── docker-compose.yml
├── pnpm-workspace.yaml
└── turbo.json
```

## Quick start

Prerequisites: Node.js ≥ 20, pnpm 9 (corepack), Python 3.11+ for `apps/ai`, and
Docker + Docker Compose for PostgreSQL / Redis / MinIO.

```bash
cp .env.example .env          # local values only — never commit .env
pnpm install
docker compose up -d postgres redis minio minio-init
pnpm db:generate              # Prisma client
pnpm db:migrate               # apply migrations to the local database
pnpm db:seed                  # tool catalog metadata (no commands, nothing executed)
```

> No Docker available? `scripts/local-stack/` runs the same stack Docker-less
> (local PostgreSQL / Redis / MinIO binaries) with `start.sh` / `stop.sh`, plus
> the live smoke scripts used for the 296-check regression.

Development commands:

```bash
pnpm dev          # all apps (turbo)
pnpm build        # build everything
pnpm lint
pnpm typecheck
pnpm test         # TypeScript suites
pnpm test:ai      # Python tests for apps/ai
```

Run one app: `pnpm --filter @zerosweep/web dev` (port 3000),
`pnpm --filter @zerosweep/api dev` (port 4000), `pnpm --filter @zerosweep/worker dev`,
`cd apps/ai && uvicorn app.main:app --port 8000`.

Health checks: API `GET /api/v1/health` (api / postgres / redis / minio / ai),
liveness at `GET /api/v1/health/live`, AI `GET /health`, worker heartbeat logs.

## API (versioned, /api/v1)

`auth` (register / login / me) · `users` · `organizations` · `workspaces` ·
`targets` (+ `/verifications`) · `scopes` · `assessments` (+ `/approve`) ·
`scans` (+ `/cancel`) · `findings` · `reports` · `tools` (+ `/categories`,
`/capabilities`, `/:id/health`) · `integrations` · `credentials` (metadata only) ·
`audit-logs` · `notifications` · `health`.

There is deliberately **no** execute/command endpoint.

## Testing

- **2,140 TypeScript tests** across the monorepo (validation, scope & policy,
  RBAC, tenant isolation, state machines, adapters, risk engine, reporting,
  platform operations, SaaS licensing) and **6 Python tests** for the AI service.
- **Live regression: 296/296 checks** across the 14 committed smoke scripts in
  `scripts/local-stack/` — register → verify → approve → scan → findings, plus
  one smoke per major subsystem, all fixture-only.
- Safety rules are tested, not just documented: intrusive/exploit/brute/DoS
  capabilities are policy-excluded in code with tests that keep them excluded.

## Phase map

Built incrementally from the 40-prompt master spec, one phase per prompt, each
verified before the next began:

| # | Phase | # | Phase |
|---|---|---|---|
| 1 | Master architecture | 21 | AI Security Copilot |
| 2 | Monorepo, backend & database foundation | 22 | Continuous monitoring & scheduler |
| 3 | Tool Adapter SDK & registry | 23 | Enterprise auth, SSO, MFA & SCIM |
| 4 | Scan orchestration, DAG, workers & live progress | 24 | Integrations & DevSecOps |
| 5 | Recon & asset discovery | 25 | Enterprise deployment, HA & DR |
| 6 | Web attack-surface discovery | 26 | Compliance, audit & GRC |
| 7 | Safe vuln detection, TLS, normalization & correlation | 27 | Security data lake & analytics |
| 8 | ZAP / Burp / Caido connectors | 28 | SOC, SIEM & threat intelligence |
| 9 | API security | 29 | External attack surface management (EASM) |
| 10 | Network VAPT | 30 | Advanced vulnerability intelligence |
| 11 | Vulnerability management & intelligence | 31 | Remediation orchestration & SLA |
| 12 | Source code security | 32 | Advanced web & API VAPT V2 |
| 13 | Container, Docker & Kubernetes security | 33 | Advanced network VAPT V2 |
| 14 | Multi-cloud security | 34 | Advanced cloud & container V2 |
| 15 | Active Directory assessment | 35 | Advanced mobile & binary V2 |
| 16 | Controlled pentest validation | 36 | AI Copilot V2 |
| 17 | Mobile application VAPT | 37 | Reporting & client portal V2 |
| 18 | Reverse engineering & binary analysis | 38 | Production deployment & observability V2 |
| 19 | Wireless assessment (passive) | 39 | Final hardening, QA & release candidate |
| 20 | Unified reporting & dashboard | 40 | SaaS productization, licensing & v1.0 launch |

## Deployment paths

- **Demo (live now)** — the merged single-container deployment on Oracle
  Cloud (the `render.yaml` blueprint remains in the repo for a Render-based
  redeploy). See [Live deployment](#live-deployment).
- **Production** — `deploy/` carries the real topology: hardened multi-stage
  Dockerfiles, Compose profiles, Helm charts (with HPA / PDB / NetworkPolicy),
  backup & DR runbooks, and observability configs (Prometheus, Grafana,
  Alertmanager, Loki, OTel).
- **CI** — a complete production workflow (SBOM / SAST / migration gates,
  approval-gated deploys) lives at `deploy/ci/production-ci.yml` with an
  activation note; it moves under `.github/workflows/` unchanged.

## Known limitations (honest list)

- **Object storage on the demo** — a private Supabase Storage bucket
  (S3-compatible) is wired in, so object storage reports ok in the live
  health check.
- **Live transports unwired** — cloud / directory / Kubernetes provider
  transports are deliberately not connected in this build; affected features
  report `NOT_CONFIGURED` / `UNAVAILABLE` honestly rather than fabricating data.
- **Intel dataset** — the production vulnerability-intel dataset stays
  `NEVER_SYNCED`; fixture imports are provenance-labelled and never advance
  sync state.
- **Docker** — the reference local stack was proven Docker-less on the build
  machine; the Compose/Helm paths are shipped and reviewed but were not run
  against a live cluster in this environment.
- **Post-RC1 items** — a Next.js 15/16 migration (clears vendored-library
  advisories that are build-time-only) and `/vulnerabilities` list latency
  (~357 ms mean measured) are tracked in `docs/release/rc1-findings.md`.
- **License** — no open-source license file is included; the product-licensing
  machinery (Phase 40) is implemented, but the repository's legal terms are the
  owner's decision and have intentionally not been chosen here.

## Documentation

- `docs/architecture/` — system design, boundaries, data ownership
- `docs/release/` — RC1 audit & findings, release guides, operations handoff
- `docs/operations/` — runbooks and day-2 operations
- `release/v1.0/` — v1.0 packaging (changelog, checksums, release notes draft)

## History

ZeroSweep was built end-to-end on 2026-10-07 → 2026-10-08 as 40 sequential,
individually verified phases on this single repository — no phase was started
before the previous one passed its tests and live smoke. The full per-phase
record is the git history of this repo; release-candidate findings and the
launch-gate evaluation are in `docs/release/`.
