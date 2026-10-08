# DSRclone — Authorized Automated VAPT Platform

DSRclone is a **GUI-first** automated VAPT (Vulnerability Assessment & Penetration
Testing) and security-assessment orchestration platform. An authorized user registers
a target, **verifies ownership**, defines **scope**, chooses an assessment profile,
and DSRclone orchestrates security tools through standard adapters, normalizes and
deduplicates their findings, scores risk, and generates professional reports.

The user never touches a command line: every workflow is clicks, forms and buttons.
Security tools run only inside isolated workers — never in the web server, and never
without verified scope and approval.

> **Status — Phase 32 complete (Prompts 1–32).** Production monorepo, backend and
> database foundation, the complete Tool Adapter SDK, a 129-tool metadata
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
> registered in-product, which is a product state, not an error. And now
> the **API security layer**: guarded OpenAPI/Swagger, Postman, Insomnia
> and GraphQL schema imports (hostile-input limits, secrets dropped to
> reference names, inventory only — never findings), an API operation
> policy that classifies every operation SAFE / STATE_CHANGING /
> DESTRUCTIVE_UNKNOWN / REVIEW_REQUIRED and keeps state-changing work
> out of automation entirely, Kiterunner route discovery, Schemathesis
> safe schema testing, InQL/GraphQLmap GraphQL inventory, decode-only
> JWT inspection (fingerprints + redacted claims; tokens never stored;
> cracking forbidden), mitmproxy traffic import, and the full
> API_ASSESSMENT pipeline flowing into the same normalization →
> correlation → risk tail. And now the **network VAPT engine**: CIDR
> canonicalization + size policy, protected-destination rules (private
> ranges need an approved internal engagement; loopback/metadata/platform
> networks are always denied), bounded target expansion (chunks, never
> millions of rows), and eight adapters on the SDK lifecycle — Nmap
> (typed plans only, a governed NSE script policy that can never select
> intrusive/brute/exploit scripts, hostile-input XML parsing), Naabu,
> RustScan (no downstream-command passthrough), Masscan (never
> auto-selected, administrator-approval gated, hard-clamped), Netdiscover
> + arp-scan (internal layer-2 workers only), tcpdump (bounded capture)
> and tshark (offline analysis). Multi-scanner ports merge into one
> canonical service with provenance; open ports are inventory — findings
> come only from governed safe checks (cleartext services, the
> unauthenticated Docker API, script-confirmed conditions), while
> database/remote-admin services are exposure records with no login ever
> attempted. Four network profiles (DISCOVERY / BASELINE /
> COMPREHENSIVE / INTERNAL) plus NETWORK_ASSESSMENT run the full DAG
> into the same correlation/risk tail; a /network GUI shows networks,
> hosts, ports/services, captures and tool health. Wireshark stays a
> manual analyst tool whose captures are imported. Everything
> runs only inside approved scans against verified, in-scope targets.
> Adapters whose binaries are absent report UNAVAILABLE honestly and
> pipelines degrade — nothing fakes a real run. The AI service has no LLM
> connected yet. And now the **container, Docker & Kubernetes layer**:
> digest-bound image inventory with drift snapshots and purely static
> analysis (Trivy vuln/misconfig/secret kinds kept separate, Syft
> inventories + on-demand SBOMs, the Prompt 12 Grype adapter extended to
> images — Trivy+Grype merge into one canonical finding per CVE), CIS
> benchmark posture via Docker Bench / kube-bench as INTERNAL_PRIVILEGED
> adapters that only a dedicated privileged worker can run, a read-only
> Kubernetes connector (clusters registered by reference; secret values
> never retrieved) with a full posture engine (privileged pods, hostPath,
> RBAC, NetworkPolicy, digest pinning), kube-hunter passive-only by
> policy, Kubescape + Checkov manifest analysis under hostile-YAML
> discipline, CIS/NSA-CISA control assessments (evidence, never
> certification), Falco runtime-event ingestion (sanitized detections,
> never vulnerabilities), and /containers, /kubernetes, /compliance and
> /runtime-events GUIs. No image is ever executed and no Docker socket
> is mounted anywhere. And now the **multi-cloud security layer**:
> AWS/Azure/GCP accounts registered as verified targets and assessed
> READ-ONLY forever (no code path creates, modifies or deletes a cloud
> resource; credentials exist only as secret-reference names resolved
> under job-scoped leases inside an isolated CLOUD_ANALYSIS worker),
> normalized resource/identity inventory with evidence-based exposure
> classification, IAM policy analysis over hardened parsers (policy
> documents are untrusted input), Prowler/ScoutSuite/Steampipe CSPM on
> canonical rules that merge with native analysis into one finding per
> issue, CloudMapper/ROADtools defensive imports, Pacu registered
> DISABLED with no adapter, CIS AWS/Azure/GCP control assessments on
> the Phase 13 compliance framework, snapshot + IaC drift, risk paths,
> and a /cloud-security GUI. Unconfigured accounts honestly report
> NOT_CONFIGURED — inventory is never fabricated.
> And now the **enterprise integrations & DevSecOps layer**: a registry
> of per-workspace integration instances (GitHub, GitLab, Bitbucket,
> Jira, Slack, Microsoft Teams, SIEM, generic webhooks) holding secret
> REFERENCES only — configuration schemas reject secret values
> outright, and no API or UI surface can display one. Inbound provider
> webhooks are hostile input: HMAC/token signature verification BEFORE
> parsing trust, size caps, delivery-id replay protection, tenant
> binding, and a repository allowlist (the link table) — and a webhook
> can only trigger a governed scan of a VERIFIED target under an
> already-APPROVED assessment with fresh-DNS scope revalidation; it
> can never approve anything. PR/MR assessments classify findings
> against immutable per-commit baselines (NEW / PRE_EXISTING /
> REGRESSED) and a typed quality-gate engine (FAIL_CLOSED default)
> decides merge/deploy readiness; CI pipelines use scoped
> service-account API keys and receive counts + redacted locations
> only — never secret values — plus scrubbed SARIF 2.1.0. Jira tickets
> are created once per finding (duplicates prevented), sync
> bidirectionally with three-way conflict detection (never silent
> overwrite), and a CLOSED ticket is never a resolved finding. All
> outbound delivery (Slack/Teams alerts, SIEM export in JSON/CEF/LEEF,
> signed generic webhooks) flows through a transactional outbox with
> bounded retries, backoff, circuit breaking and dead-lettering, and
> every destination is SSRF-validated — including every redirect hop
> with fresh DNS. Provider transports are unwired in this environment,
> so everything honestly reports NOT_CONFIGURED; verification is
> fixture-payload/mock-transport only.

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
9. ✅ API security testing & protection assessment (Prompt 9)
10. ✅ Network VAPT engine (Prompt 10)
11. ✅ Vulnerability management & intelligence (Prompt 11) 20. Unified reporting & dashboard
12. ✅ Source code security: SAST, secrets & SCA (Prompt 12)
13. ✅ Container, Docker & Kubernetes security (Prompt 13)
14. ✅ Multi-cloud security assessment: AWS, Azure & GCP (Prompt 14)
15. ✅ Active Directory security assessment, identity graph & defensive attack-path engine (Prompt 15)
16. ✅ Controlled penetration testing & validation workflow (Prompt 16)
17. ✅ Mobile application VAPT — Android & iOS (Prompt 17)
18. ✅ Reverse engineering & binary analysis (Prompt 18)
19. ✅ Wireless security assessment — passive only (Prompt 19)
20. ✅ Unified vulnerability management, reporting & executive dashboard (Prompt 20)
21. ✅ AI Security Copilot & intelligent analysis engine (Prompt 21)
22. ✅ Continuous monitoring, intelligent scheduler & change detection (Prompt 22)
23. ✅ Enterprise authentication, SSO, MFA, SCIM & organization management (Prompt 23)
24. ✅ Enterprise integrations, DevSecOps & security workflow engine (Prompt 24)
25. ✅ Enterprise deployment, Kubernetes, high availability, backup/DR & production hardening (Prompt 25) — incl. the first fully live end-to-end run: Docker-less local PostgreSQL/Redis, all migrations + seed applied, register→verify→approve→scan→findings proven (see `scripts/local-stack/`)
26. ✅ Compliance, Audit & GRC platform (Prompt 26) — versioned framework catalog (ISO 27001, SOC 2, PCI DSS 4.0, NIST CSF/800-53, CIS Controls, OWASP), control library with cross-framework mappings, snapshot evidence + freshness, continuous control monitoring, risk register, audit packages; assessment evidence, never certification — GRC migration also applied to the live local stack
27. ✅ Security data lake, advanced analytics, attack-surface intelligence & enterprise search (Prompt 27) — append-only canonical event lake with idempotent ingestion + dead-letter quarantine, lifecycle/risk projections, governed DSL search (tenant + classification enforced before retrieval, secrets redacted at index time), correlation signals, evidence-backed attack-path candidates, MTTR/SLA/regression analytics over real records only; data-lake migration also applied to the live local stack
28. ✅ Enterprise SOC, SIEM, detection engineering, threat intelligence & incident response (Prompt 28) — canonical telemetry store (scoped ingestion auth, fingerprint idempotency, content hashes, secret redaction before storage), safe declarative detection DSL with immutable rule versions and ATT&CK-mapped templates, fingerprint-deduped alerts with a deterministic priority engine and scoped expiring suppressions, incidents with append-only timelines and hash-anchored access-logged evidence, STIX/fixture threat-intel with provenance + deterministic confidence (live transports NOT_CONFIGURED, honestly), SOC correlation over the Prompt 27 engine, a closed response-action catalog behind single/dual approval with segregation of duties, declarative playbooks, SIEM forwarding only through the Prompt 24 governed outbox, and SOC analytics over recorded rows only; SOC migration also applied to the live local stack
29. ✅ Enterprise External Attack Surface Management (Prompt 29) — EASM programs + root assets with challenge-based ownership verification and a SEPARATE, segregated active-testing grant (discovered assets land UNVERIFIED/UNMANAGED with activeTestingStatus NOT_AUTHORIZED and can never be scanned without the standard VERIFIED + APPROVED gates), passive-first discovery via governed adapters (live transports NOT_CONFIGURED, honestly), normalization/dedup with wildcard suppression, DNS intelligence with snapshot history + dangling-DNS *candidates* (never claimed takeovers), certificate intelligence (SAN → candidate only), approved-port service discovery and redirect-recording HTTP discovery for authorized roots only, independent-source technology confidence (family-only ⇒ version null), evidence-based ownership resolution, promotion to canonical assets that stay UNVERIFIED, immutable drift baselines with flapping control and threshold disappearance, risk signals into RiskEngine V3 context + P28 SOC alerts, continuous monitoring on the P22 scheduler (discovery-class only), grounded AI copilot that cannot authorize, and an 8-page EASM console; EASM migration also applied to the live local stack
30. ✅ Advanced Vulnerability Intelligence (Prompt 30) — a deepened intel layer over Prompt 11: per-field source provenance on every CVE record, multi-source/multi-version CVSS preserved with deterministic preferred selection, append-only EPSS history with staleness (missing EPSS is null, never 0), the full KEV catalog lifecycle (add/update/remove + transition events that re-evaluate affected findings, recalculate Risk V3 and notify exposed workspaces via P22 policies), software product/PURL/CPE identity with identifier mappings, ecosystem-aware branch-specific version ranges (never flattened), advisory dedup + patch intelligence that never invents a fix (source disagreement on the fixed version is shown, never silently resolved), SBOM correlation over the Prompt 12 subsystem with match evidence (heuristic/name-only matches are POTENTIALLY_AFFECTED only — never confirmed, never cleared; scanner disagreement preserved verbatim), defensive-only exploit context (metadata + references; no exploit code stored/fetched/executed, ever), reachability where NOT_REACHABLE requires positive evidence, blast radius with confirmed vs potential always separate, explainable multi-factor prioritization (never CVSS-only) feeding a remediation queue, KEV/EPSS/patch/intelligence dashboards + typed-filter search + analytics (KEV response times, patch latency, three separate vulnerability ages), a grounded AI copilot that states the governed no-fix sentence verbatim, governed snapshot import with checksums (fixture imports are provenance-labelled and never advance sync state — the shipped dataset stays NEVER_SYNCED and live sync attempts honestly record NOT_CONFIGURED), and a 7-page console (intelligence dashboard, remediation queue, KEV, EPSS, patches, deep CVE detail, SBOM explorer + component detail); VI migration also applied to the live local stack
31. ✅ Enterprise Remediation Orchestration, Ticketing, SLA Management, Fix Verification & Vulnerability Lifecycle Automation (Prompt 31) — one ACTIVE remediation case per canonical finding with an append-only status history (NEW → TRIAGED → ASSIGNED → PLANNED → IN_PROGRESS → FIX_CLAIMED → VERIFICATION_* → VERIFIED_FIXED → CLOSED, plus ACCEPTED_RISK / FALSE_POSITIVE / DEFERRED / REOPENED) whose guarded state machine makes VERIFIED_FIXED reachable ONLY through the verification engine and CLOSED only through the closure engine (a closed ticket, a developer's say-so, a quiet scanner or an AI can never mark anything fixed); triage with evidence-bound false positives and canonical duplicate handling; deterministic ownership resolution (AI may suggest, never assign); SLA policies as versioned configuration with resolution snapshots, configured pause reasons, a breach/warning tick that notifies through the P22 router, and a no-silent-shortening recalculation guard; evidence-backed plans whose fixed version must trace to Prompt 30 Patch Intelligence (invented versions rejected for humans and AI alike); canonical work items before provider tickets with allowlist-only secret-scrubbed payloads, idempotent creation, FAILED + backoff on provider failure (transports NOT_CONFIGURED honestly), and ticket-closed → fix-claimed (never verified) sync; a fix-verification engine whose rescan/retest methods ride the governed Prompt 11 retest gates (denials recorded, never bypassed), with before/after evidence, scanner ERROR ≠ pass, INCONCLUSIVE on weak evidence, multi-observation confirmation and SoD + dual approval for high-risk manual verification; closure snapshots preserving verification/risk/ticket/SLA/exception state; a regression engine (fingerprint identity → reopen case + finding, risk recalculated, owner notified); exceptions that reuse the P20 RiskException record (no duplicate acceptance system), always expire, and return findings to the actionable workflow; campaigns with progress computed from live case states; bounded bulk actions that structurally exclude verify/close; remediation analytics with the three distinct §111 MTTR clocks (claim / verify / close — never mixed with SOC MTTR-IR); a grounded AI assistant that cannot mark anything fixed; deterministic NL search; state-preserving report snapshots; and a 5-page remediation console (queue, case detail with 11 tabs, SLA, campaigns, regressions); remediation migration also applied to the live local stack with a 19/19 live lifecycle smoke
32. ✅ Advanced Web Application & API VAPT Orchestration Engine V2 (Prompt 32) — a deepening of the Prompt 5–9 engines on the same canonical models: a 28-tool capability registry with PASSIVE/LOW/MODERATE/HIGH risk classes (no destructive class exists) and a §16 gate that keeps HIGH modules (SQLmap/Commix/SSTImap) out of every named profile unless profile + active authorization + RUN_HIGH_RISK_WEB_TESTS + recorded approval all hold; WebVaptTargets bound to VERIFIED assets + APPROVED assessments; preflight over real authorization facts with an honestly NOT_CONFIGURED probe transport (BLOCKED, never assumed READY); immutable hashed scope snapshots (mid-run changes never expand, new hosts candidate-only, metadata destinations blocked, out-of-scope redirects recorded never followed); plan previews with one-directional budget clamping to the platform ceiling; canonical endpoint identity (method + templated path, volatile values excluded) with multi-tool content-discovery merge and dangerous-path exclusion from automatic interaction; contextual header/CORS/CSRF analysis; GraphQL generation bounds; authorization test matrices over Prompt 9 design records (mismatch → CWE-862 candidate finding, fixture identifiers only) and human-defined safe-step business-logic scenarios; six governed detection-only adapters (Dalfox/XSStrike safe-marker XSS, SQLmap boolean detection with dump/shell/file options structurally rejected, Commix/SSTImap marker detection, WPScan enumeration with password attacks rejected) with structured parsers whose failure is partial, never clean; planted-fixture-credential redaction asserted in tests; honest coverage (null = not measured) + tool health (UNAVAILABLE, never faked); a constrained AI copilot that refuses scope expansion and destructive enablement; and a 4-page VAPT console (/vapt/web, /vapt/api, target detail with plan preview, scan detail with coverage); web-vapt migration also applied to the live local stack

## Changelog

- **2026-10-08 — Prompt 32: Advanced Web Application & API VAPT
  Orchestration Engine V2.** Deepens Prompts 5–9 without parallel
  systems: SDK core `packages/security-sdk/src/webvapt/` (capability
  registry + risk classes, module gate, budgets, scope lock, preflight,
  endpoint identity/merge, header/CORS/CSRF analysis, GraphQL limits,
  authorization matrices + business-logic validation, profiles,
  coverage + tool health, detection-only parsers/adapters for Dalfox,
  XSStrike, SQLmap, Commix, SSTImap, WPScan — registered in the worker
  alongside all prior families), six new taxonomy classes, 11 new
  models (WebVaptTarget, ScanScopeSnapshot, WebVaptScanPlan,
  WebVaptPreflightResult, ApiSpecificationSnapshot,
  AuthorizationMatrixEntry, BusinessLogicScenario, WebScanSession,
  WebVaptEvidence, WebVaptCoverage, WebToolHealth), 11 new audit
  actions, the `/api/v1/vapt/*` surface (§165) with §166/§167
  permissions, and four console pages. Governance is unchanged and
  structural: VERIFIED + APPROVED before any target, detection-only
  adapters with forbidden options actively rejected, secret references
  only, fixture-only verification, parser failure = partial never
  clean. Migration applied to the live local stack; live smoke covers
  target → plan (gate + clamp + snapshot hash) → preflight (honest
  BLOCKED) → spec import host validation → matrix candidate → tool
  health/coverage.
- **2026-10-08 — Prompt 31: Enterprise Remediation Orchestration,
  Ticketing, SLA Management, Fix Verification & Vulnerability
  Lifecycle Automation.** Adds the remediation orchestration layer
  over Prompts 11/20/24/30: a deterministic SDK core
  (`packages/security-sdk/src/remediation/` — state machine, ownership,
  SLA resolution/derivation/recalculation guard, verification policy +
  evaluation, ticket payload builder with secret scrubbing, campaign
  progress, analytics, NL query plans), 16 new models (cases, status
  history, triage, assignments, SLA snapshots + pauses, plans, work
  items, fix claims, verification jobs + evidence, exceptions,
  campaigns, regression events, report snapshots), 21 new audit
  actions, and the full `/api/v1/remediation/*` surface (§118) with
  §121 permissions and §122 segregation of duties. Verified
  fixture-only (31 API tests + 29 SDK tests) and live (19/19 smoke:
  register → scan → case → SLA → triage → assign → claim →
  verification → VERIFIED_FIXED → closure → finding RESOLVED on the
  Docker-less local stack).
- **2026-10-08 — Prompt 30: Advanced Vulnerability Intelligence,
  CVE/CWE/CVSS/EPSS/KEV Enrichment, SBOM Correlation & Patch
  Intelligence.** Expands the Prompt 11 intelligence subsystem with a
  deterministic SDK layer (`packages/security-sdk/src/vulnintel/`) and
  19 new models: canonical CVE records with per-field provenance,
  per-source CVSS assessments (history never rewritten; preferred
  value selected by source priority → version → score), append-only
  EPSS history with freshness, the KEV lifecycle (catalog events,
  removals as data, affected-finding re-evaluation + Risk V3
  recalculation + policy notification on entry), product/PURL/CPE
  identity + mappings, branch-aware affected ranges, advisory dedup
  and patch intelligence (agreements cite a fixed version;
  disagreements are preserved and presented as disagreements), SBOM
  correlation with typed match evidence (scanner disagreement
  downgrades to POTENTIALLY_AFFECTED with both observations kept;
  heuristic matches never confirm), exploit context as defensive
  metadata only, reachability with positive-evidence NOT_REACHABLE,
  blast radius with confirmed/potential separation, explainable
  prioritization + remediation queue, dashboards/search/analytics, a
  grounded copilot (verbatim no-fix sentence; numeric answers from
  stored values only), and governed snapshot import — recorded
  fixture feeds in tests, fixture imports provenance-labelled and
  never advancing the NEVER_SYNCED dataset state; live transports
  remain honestly NOT_CONFIGURED.

- **2026-10-08 — Prompt 29: Enterprise External Attack Surface
  Management (EASM).** An external-surface layer over the asset
  inventory, RiskEngine V3, the P22 scheduler, P27 correlation and
  the P28 SOC alert path. Programs own root assets whose ownership is
  proven by a published DNS TXT / file challenge (or recorded manual
  approval); active testing is a second, separate grant restricted to
  OWNER/ADMIN. Discovery is passive-first through governed adapters:
  results land as candidates with full provenance, normalized and
  deduplicated (domain/IDN/IP/URL/certificate/technology), with
  wildcard-zone suppression for uncorroborated labels. DNS snapshots
  are append-only history with typed diffs; unresolvable CNAMEs to
  claimable services become dangling-DNS *candidates* with evidence —
  never claimed takeovers. Certificate intelligence tracks expiry
  states and treats every SAN as a candidate only. Service discovery
  and HTTP probing run solely for VERIFIED + active-authorized roots,
  on approved port sets, with redirects recorded and never followed.
  Ownership resolves from weighted evidence (rules can be decisive);
  promotion creates canonical assets that remain UNVERIFIED until the
  standard gates pass. Drift compares against immutable hashed
  baselines with flapping control and multi-run disappearance;
  sensitive exposure raises governed SOC alerts. Continuous runs ride
  P22 schedules (HOURLY_LIGHT / DAILY / WEEKLY_DEEP tiers,
  discovery-class only). The grounded EASM copilot cites records and
  refuses authorization requests. EASM GUI at `/easm`, `/easm/assets`,
  `/easm/assets/:id`, `/easm/unknown-assets`, `/easm/discovery`,
  `/easm/drift`, `/easm/technologies`, `/easm/certificates`.
- **2026-10-08 — Prompt 28: Enterprise SOC, SIEM, Detection Engineering,
  Threat Intelligence & Incident Response Engine.** A SOC layer over the
  existing event bus/outbox (P24), data lake + correlation (P27),
  notifications (P22) and identity (P23): telemetry lands in a canonical
  store through scoped ingestion auth with fingerprint idempotency and
  pre-storage secret redaction; a safe declarative DSL (no code can exist
  in a rule) drives versioned detections with ATT&CK-mapped templates;
  alerts dedupe by fingerprint under a deterministic priority engine
  with scoped, expiring suppressions; incidents run append-only
  timelines, hash-anchored evidence with logged access, and declarative
  playbooks; threat intelligence is fixture-imported STIX with per-source
  provenance and deterministic confidence (live transports report
  NOT_CONFIGURED); response is a closed catalog of nine defensive
  actions behind single/dual approval with segregation of duties and
  idempotent execution; SIEM forwarding rides the governed outbox only.
  SOC GUI at `/soc`, `/soc/alerts`, `/soc/incidents`, `/soc/detections`,
  `/soc/threat-intelligence` and `/analytics/soc`.
- **2026-10-08 — Prompt 27: Security Data Lake, Advanced Analytics,
  Attack Surface Intelligence & Enterprise Search Engine.** A logical
  data lake over PostgreSQL: canonical security events land append-only
  through a validating ingestion pipeline (transactional outbox +
  finding-history consumers, per-partition checkpoints, poison records
  quarantined in a dead-letter with machine codes — never dropped).
  Lifecycle and risk-history projections are pure functions of landed
  events, so rebuilds are deterministic. Enterprise search indexes
  redacted documents (secrets removed before indexing) and enforces
  tenant scope + classification ceiling in the query itself; the
  governed query DSL is allowlisted and evaluated over typed records —
  no user input ever becomes SQL, and natural-language questions are
  translated to the same DSL deterministically. Correlation rules
  produce fingerprint-deduped signals; attack-path candidates chain
  internet → asset → finding → sensitive downstream with evidence on
  every edge and are labelled analyst aids, never exploitation
  procedures. Analytics (overview, vulnerabilities, attack surface,
  DevSecOps, cloud, identity, GRC) compute only over real records —
  empty stays empty, MTTR excludes unresolved findings, growth needs
  two snapshots. Retention deletes lake-owned records only; the audit
  trail is untouchable. GUI: /analytics (+5 sub-dashboards) and
  /search. Migration `20261008033253_security_data_lake` applied to
  the live local stack.

- **2026-10-08 — Prompt 26: Compliance, Audit & GRC Platform.** The GRC
  engine layers over the platform's identity, findings, posture and
  audit systems (no duplicate VM or audit log). Versioned framework
  catalog (ISO/IEC 27001:2022, SOC 2 TSC 2017, PCI DSS 4.0, NIST CSF
  2.0, NIST SP 800-53 Rev. 5, CIS Controls v8, OWASP ASVS 4.0.3 + Top
  10) with immutable published versions and assessments pinned to the
  version they were created against; a 30-control normalized library
  with ~110 cross-framework mappings under coverage discipline (a
  PARTIAL/SUPPORTING mapping can never make a requirement compliant);
  control evaluation from real platform signals only — no evidence
  means INCONCLUSIVE / NOT_ASSESSED, never a pass; snapshot evidence
  sealed with SHA-256 and per-control freshness policies (CURRENT →
  STALE → EXPIRED), hostile-upload defenses, review segregation of
  duties, RESTRICTED evidence withheld by capability; continuous
  control monitoring with drift events and targeted re-evaluation;
  a risk register whose residual score exists only when control
  effectiveness is known, with SoD-guarded, expiring acceptances;
  versioned governance policies with explicit acknowledgements; audit
  engagements, evidence requests, audit findings kept separate from
  technical findings, and CONFIDENTIAL evidence packages sealed by a
  hash manifest with redaction and expiring explicit-share auditor
  grants; finding→control links; vendor risk foundation; a grounded
  AI GRC assistant that refuses certification claims and answers
  INSUFFICIENT_EVIDENCE without evidence; immutable report snapshots
  and GRC backup/restore with hash verification. **No certification
  claims anywhere** — the headline metric is "Assessment Coverage /
  Control Status". Migration `20261007220000_enterprise_grc` applied
  to the live local stack.
- **2026-10-08 — Prompt 25: Enterprise Deployment, High Availability &
  Disaster Recovery.** New `deploy/` tree: hardened multi-stage production
  images (digest-pinned bases, non-root), production Compose profile
  (secrets from external env only), canonical Kustomize base + dev/staging/
  production overlays (Helm chart as equivalent subset), worker pools per
  the ScannerCapabilityPolicy, default-deny NetworkPolicies, restricted
  Pod Security, admission policies (Kyverno), Prometheus rules for the
  operational + security alert lists, backup tooling with automated
  restore verification (incl. tenant-isolation checks), DR design +
  runbooks, production config fail-fast gate (`validateProductionConfig`),
  `/health/live` + `/health/ready` probe endpoints, `/metrics`, and a
  standalone lease-guarded scheduler process. **First live end-to-end
  verification in the project's history**: a Docker-less local stack
  (PostgreSQL 16.2 via pgserver binaries, Redis 7.2.5 from source) ran all
  22 migrations + the seed (fixing two latent seed bugs found in the
  process), booted API/worker/AI, and passed a 13/13 register→login→
  target→verify→scope→assessment→approve→scan→COMPLETED smoke with real
  persisted findings, a 4/4 resilience subset (API restart durability,
  Redis-pause readiness/liveness split, scheduler-lease exclusivity,
  production config refusal), and a RESTORE_VERIFIED backup cycle.
  Reproduce with `scripts/local-stack/`. MinIO's binary could not be
  fetched in this environment (410/404 from both official channels), so
  object storage reports `down` honestly in the local stack.
- **2026-10-08 — Prompt 24: Enterprise Integrations, DevSecOps &
  Security Workflow Engine.** The `Integration` registry was extended
  in place (P20 connectors keep working): GitHub/GitLab/Bitbucket
  source control, Jira ticketing, Slack/Teams messaging, SIEM export
  and generic webhooks behind one SDK connector contract; credentials
  exist only as secret references (schemas reject secret values;
  rotation swaps references). Inbound webhooks verify signatures
  before parsing, enforce size caps and delivery-id replay
  protection, bind to the verifying tenant, and trigger only governed
  scans (VERIFIED target + pre-existing APPROVED assessment +
  fresh-DNS scope revalidation — no path approves anything).
  Diff-aware PR/MR assessments classify findings vs immutable
  per-commit baselines; the typed quality-gate engine (presets,
  FAIL_CLOSED/WARN/FAIL_OPEN scanner-failure policy) publishes
  verdicts to CI through scoped service-account keys
  (`pipelines:security-scan`, `pipelines:gate-read`) with
  secret-free sanitized summaries and SARIF 2.1.0. Jira sync is
  three-way with conflict records and never touches the finding
  lifecycle. Outbound delivery is transactional-outbox based (bounded
  retries, backoff, circuit breaker, dead-letter; logically
  exactly-once after crash) with SSRF validation at subscription
  creation, at delivery, and at every redirect hop. Fixture/mock
  verification only — all live provider transports honestly report
  NOT_CONFIGURED (see docs/architecture/enterprise-integrations.md).
- **2026-10-08 — Prompt 23: Enterprise Authentication, SSO, MFA, SCIM &
  Organization Management.** Enterprise identity layered on top of the
  existing local auth (never replacing it): server-side sessions with
  hashed opaque tokens, idle/absolute policy lifetimes, immediate
  revocation and current-membership role resolution; MFA with
  AES-256-GCM-encrypted TOTP secrets, replay-protected verification,
  single-use hashed recovery codes and passkeys (WebAuthn, counter
  clone detection); OIDC (Authorization Code + PKCE, strict RS256
  ID-token validation) and SAML (dependency-free validator: XXE refused,
  enveloped rsa-sha256 only, assertion replay consumption) with JIT
  provisioning whose roles come only from approved group mappings;
  break-glass admins whose audited password logins survive SSO
  enforcement, which itself cannot be enabled without a recovery path;
  SCIM 2.0 provisioning with dedicated per-organization bearer tokens,
  a strict filter parser and disable-never-delete deprovisioning;
  service accounts and API keys with a closed typed scope catalog
  (shown once, hash-only at rest); identity governance — security and
  password policies, domain verification, single-use invitations and
  access reviews whose decisions execute real revocations. Unconfigured
  organizations honestly report SSO/SCIM NOT_CONFIGURED; verification is
  fixture-IdP only (no live IdP exists in this environment) and SAML
  encrypted assertions report NOT_SUPPORTED.
- **2026-10-08 — Prompt 22: Continuous Monitoring, Intelligent
  Scheduler & Change Detection.** Governed recurrence over the
  existing platform: monitoring policies bound to SAFE_AUTOMATED
  profiles only (approval-required/manual/prohibited automation is
  unschedulable in code, §11 list included), a lease-guarded tick
  scheduler with deterministic run keys, missed-run collapse,
  blackout/maintenance windows, concurrency + budget caps,
  backpressure and tenant fairness. Every fire time re-runs every
  gate — APPROVED assessment, VERIFIED target, fresh DNS scope
  revalidation — and refusals are persisted BLOCKED/SKIPPED runs,
  never silent retries. Schedules materialize only through the
  governed paths (orchestration scans, Prompt 20 report definitions,
  Prompt 16 validation requests that still need approval, Prompt 11
  retests via the RetestRouter + SAFE catalog). Immutable posture /
  asset / finding snapshots feed drift detection (new ports, exposure
  changes, reopened findings) and intelligence-driven Risk Engine V3
  re-scoring without re-scanning. Typed workflows (no code, loop-
  guarded), a provider-neutral notification router with dedup /
  throttle / quiet hours / escalation and SSRF-validated webhooks
  (secret references only), and a grounded RULE_BASED-labelled daily
  summary. Honest states preserved: intel sync NOT_CONFIGURED (the
  dataset stays NEVER_SYNCED), external notification providers
  RECORDED_NOT_DELIVERED until configured.
- **2026-10-08 — Prompt 21: AI Security Copilot & Intelligent
  Analysis Engine.** An analyst-assistant layer over normalized
  platform data only: provider abstraction + model registry (secret
  references only, never values), task policy (ALLOW / DENY /
  REQUIRE_REDACTION / REQUIRE_REVIEW), least-context builder with RBAC
  before retrieval and tenant filtering at the data layer, redaction
  before any provider call (SECRET data never leaves for external
  providers), prompt-injection detection with strict instruction/data
  separation, grounding + citations + confidence (insufficient
  evidence is stated, never papered over), natural-language search via
  a governed typed DSL (never AI-generated SQL), tenant-scoped
  knowledge base + vectors, review-only suggested patches, and action
  PROPOSALS that only the existing workflows can execute. No provider
  configured ⇒ honest NOT_CONFIGURED with labelled rule-based
  summaries; the core platform never depends on AI. Golden evaluation
  suite covers groundedness, hallucination refusal, injection,
  secret-leak, cross-tenant and vector isolation.
- **2026-10-08 — Prompt 20: Unified Vulnerability Management, Reporting
  & Executive Dashboard.** All engines from Prompts 3–19 converge on
  one canonical finding model: standardized lifecycle (now with
  REOPENED/DUPLICATE/MITIGATED), priority P0–P4 kept separate from
  severity, domain-prefixed fingerprint deduplication V2, a
  correlation engine (EXPOSES/RELATED/SAME_ROOT_CAUSE chains and
  clusters — a shared CWE alone never correlates), explainable Risk
  Engine V3 (signed signals + what information is missing), ownership
  rules that never override a manual assignment, a full SLA engine
  (triage/remediation/retest timers, pausable only with a reason),
  risk exceptions with separation-of-duties approval and automatic
  expiry, and a RetestRouter that sends each domain to its own safe
  retest path (no evidence = INCONCLUSIVE, never resolved).
  DefectDojo/Faraday/Dradis/PlexTrac/Serpico connectors import with
  preview → idempotent commit; disagreements become conflicts, never
  silent overwrites (external platforms are never authoritative).
  Reporting renders fifteen report types from an IMMUTABLE,
  content-hashed snapshot built from stored findings only — PDF/
  HTML/JSON/CSV rendered asynchronously by the worker into object
  storage; snapshots are redacted once at build time so no
  secret-shaped value reaches any export; approvals flow DRAFT →
  REVIEW → APPROVED → ISSUED and an issued report can never be
  regenerated in place; downloads are permission-checked and
  audited. Executive/security/remediation/asset dashboards aggregate
  stored records only — unknown coverage is shown as unknown, never
  as 100%. Connector HTTP transports are not wired in this build:
  health and push-sync honestly report NOT_CONFIGURED, and imports
  run from administrator-supplied payloads.
- **2026-10-08 — Prompt 19: Wireless Security Assessment.** Wireless
  environments, dedicated sensors and uploaded captures became a
  first-class passive assessment domain. **Nothing transmits**: AP and
  station inventory (identity = BSSID, never the SSID), encryption /
  authentication posture per AP (open/WEP/WPA/WPA2/WPA3, PSK vs
  Enterprise, PMF, WPS — evidence-based only), rogue/unknown AP
  classification against approved profiles (SUSPICIOUS is never a
  "confirmed evil twin"), configuration drift with security-downgrade
  findings, and passive security events (a deauth burst is one event; a
  single frame never claims an attack). Kismet collects passively on
  dedicated `WIRELESS_PASSIVE_ANALYSIS` sensor workers; tshark (fixed
  field set), hcxpcapngtool and aircrack-ng (metadata only) analyze
  APPROVED captures offline. Wifite and hcxdumptool are DISABLED
  descriptors — no adapter exists, baseline profiles can never select
  them, and API requests naming them are refused + audited. Cracking,
  deauthentication, rogue-AP creation and jamming are prohibited
  automation (§99). Stations are HMAC-pseudonymized; authentication
  material in captures is counted, never stored; observed networks
  never become targets. Live RF needs sensor hardware that is not
  provisioned here, so sensor stages honestly report NOT_CONFIGURED
  and everything is verified on recorded fixture captures.
- **2026-10-08 — Prompt 18: Reverse Engineering & Binary Analysis.**
  Authorized binaries became `BINARY` targets with SHA-256 artifact
  identity: hostile-content intake (magic-byte format identification —
  a PDF-named ELF registers as ELF; SHA-1 kept for interop only), then
  STATIC analysis on isolated `BINARY_STATIC_ANALYSIS` workers —
  platform header parsing for ELF/PE/Mach-O (fail-safe on malformed
  fixtures), checksec hardening observations (NX/PIE/RELRO/canary/
  FORTIFY/ASLR/CFG with NOT_APPLICABLE discipline), the extended
  dual-mode Ghidra headless adapter (Prompt 17 adapter reused;
  approved scripts only) and radare2 typed profiles (unrestricted r2
  commands are inexpressible). Functions/imports/exports/symbols are
  inventoried with stable fingerprints; dangerous-API findings need
  function-reference evidence (an import alone is never a
  vulnerability); weak crypto is judged from imported symbols, never
  strings. Binaries are **never executed** — no running, no live
  debugging, no emulation/detonation; an embedded marker payload in
  the fixtures proves it. Dependencies bind to components + SBOMs
  (versions only where evidence exists — `libssl.so.3` yields none)
  and correlate to CVE/CVSS/EPSS/KEV against the local dataset only.
  Secrets are fingerprint-only (P12 discipline; the planted fixture
  token exists in no record). Cross-build diffs flag regressions;
  controlled debugging is a governed LAB policy (separate approver,
  kill switch, typed operations, NOT_PROVISIONED honestly when no lab
  transport exists); IDA/Binary Ninja are license-aware commercial
  connectors, Cutter an analyst-tool registration, GDB DISABLED
  outside LAB and pwndbg APPROVAL_REQUIRED — none of them execute.
  `/binary-security` GUI; migration `20261007150000_binary_security`
  generated, not applied (Docker unavailable on the build VM).
- **2026-10-08 — Prompt 17: Mobile Application VAPT — Android & iOS.**
  Mobile applications became verified `MOBILE_APP` targets with
  SHA-256 build identity: hostile-content intake (magic sniffing,
  archive-attack validation, hash enforcement, signing-metadata
  key-material dropped), then STATIC analysis on isolated
  `MOBILE_STATIC_ANALYSIS` workers — MobSF connector (trusted
  admin-registered instance only), JADX/apktool decompilation
  artifacts (never executed, RBAC-gated, audited per access), Ghidra
  native-hardening inventory (approved scripts only), manifest/plist
  analysis (permissions classified, exported components inventoried —
  presence alone is never a vulnerability), metadata-only secrets
  (type + location + HMAC fingerprint + redacted preview), and
  build-level SCA/SBOM reusing the Prompt 12 component models
  (versions never invented). Extracted endpoints are
  `DISCOVERED_REFERENCE` — they never authorize targets or expand
  scope. Findings carry OWASP Mobile Top 10 (2024) + MASVS mappings
  (no certification claims), dedupe across tools into one canonical
  finding per build, and track cross-build identity for retest.
  Dynamic work exists only in the controlled device lab
  (`MOBILE_DYNAMIC_ANALYSIS` workers, approved sessions, verified
  build hash, reset after assessment): ADB is a governed lab adapter
  — **no generic `adb shell` exists**; mitmproxy/Burp traffic is
  sanitized metadata with a temporary lab CA (never personal
  devices); Frida is a DISABLED registration and Objection
  APPROVAL_REQUIRED — instrumentation only as administrator-reviewed
  versioned modules, never arbitrary scripts. Prohibited automation
  (credential/token theft, account takeover, payment abuse,
  persistence, spyware, SMS/contact/file extraction, control bypass)
  is refused in code and audited. The mobile quality gate, budgets
  and the Prompt 16 kill switches govern every run. Migration
  `20261007140000_mobile_security` generated (not applied — no Docker
  on the build VM). Docs: `docs/architecture/mobile-security-engine.md`,
  `docs/architecture/android-security.md`, `docs/architecture/ios-security.md`,
  `docs/architecture/mobile-device-lab.md`,
  `docs/architecture/mobile-traffic-analysis.md`,
  `docs/security/mobile-artifact-sandbox.md`,
  `docs/security/mobile-dynamic-policy.md`, `docs/tools/mobile/`.
- **2026-10-08 — Prompt 16: Controlled Security Validation & Authorized
  Pentest Workflow.** Findings can now be *validated* — confidence raised
  through governed, safe rechecks — under a full control stack: a closed
  catalog of 11 SAFE validators (header/TLS/endpoint/Nuclei rechecks,
  service presence, API-safe, cloud/K8s posture, source, container, AD
  posture), immutable authorization snapshots, scope revalidation with
  fresh DNS resolution immediately before execution, plan-hash-bound
  approvals with separation of duties and expiry, strict budgets clamped
  to administrator hard limits, six-level kill switches with mid-flight
  termination, and a controlled callback service (hash-only tokens,
  tenant/session-bound, single-use). `PROHIBITED_AUTOMATION` techniques
  (spraying, dumping, Kerberoasting, relay, DCSync, RCE, …) are refused
  at plan, API and worker layers alike; offensive tools (NetExec,
  Impacket, Metasploit, …) live in a separate metadata-only registry,
  execution DISABLED. Evidence is redacted before storage and
  checksummed after; a successful safe validation sets VERIFIED
  confidence without touching the original scanner evidence, and a
  failed validation is never auto-labelled a false positive. Manual
  validation records let analysts attach sanitized evidence for
  manual-only classes (RCE findings). Validation runs only in isolated
  workers through read-only transports; the production transport is
  deliberately unprovisioned until a deployment configures governed
  egress (sessions then fail honestly, never fabricate). Scheduled
  SAFE-only revalidation is deferred to the Prompt 22 scheduler.
  Migration `20261007130000_security_validation` generated (not applied —
  no Docker on the build VM). Docs: `docs/architecture/security-validation-engine.md`,
  `docs/architecture/validation-workflow.md`,
  `docs/architecture/controlled-callback-service.md`,
  `docs/security/validation-policy.md`, `docs/security/evidence-redaction.md`,
  `docs/security/kill-switch.md`.
- **2026-10-08 — Prompt 15: Active Directory Security Assessment.** AD domains
  became verified targets (internal engagements only) with a defensive
  READ-ONLY posture: registration stores identity and a credential
  REFERENCE name under a least-privilege profile (Domain Admin is never
  requested), and collection runs only on an isolated
  `DIRECTORY_ANALYSIS` worker against explicitly approved domain
  controllers, under job-scoped leases (≤1h). BloodHound/SharpHound
  datasets, PingCastle reports and AD CS/SMB tool outputs import through
  hardened parsers (credential material stripped before persistence);
  typed LDAP queries are platform-generated only. The identity graph
  carries evidence-backed edges with provenance; posture analysis covers
  privileged-group hygiene (SID-based classification), nested groups
  (cycle-safe), stale/disabled accounts, delegation, LDAP/SMB signing,
  trusts and AD CS ESC-class template risk, mapped onto a versioned
  MS_AD_BASELINE catalog. Attack paths are computed MODELS — never
  executed, never labelled COMPROMISED. Offensive tooling (NetExec,
  Impacket, Kerbrute, Responder, PowerView, offensive Certipy) exists
  only as DISABLED registrations with no adapter; requesting one is
  refused and audited. Live directory transports are deliberately
  unwired in this build, so registered domains honestly report
  NOT_CONFIGURED until an approved internal deployment wires them.
- **2026-10-07 — Prompt 14: Multi-Cloud Security Assessment.**
  Cloud accounts (AWS/Azure/GCP) became verified targets with a
  READ_ONLY assessment posture: registration stores identity, scope
  and a credential REFERENCE name only — secret-shaped values are
  refused at the API, and the worker resolves references under
  job-scoped leases (≤1h) on an isolated `CLOUD_ANALYSIS` worker.
  Provider inventory connectors normalize resources/identities/
  relationships into assets with provider/region/service identity;
  transports expose no mutating method (read-only by construction)
  and production transports are deployment-provisioned, so
  unconfigured accounts honestly report NOT_CONFIGURED. Platform
  analysis stages (IAM, network, storage/database, encryption,
  logging) reason over the persisted inventory; IAM policy documents
  are parsed as untrusted input under hard caps. Prowler, ScoutSuite
  and governed Steampipe packs land on canonical cloud rules and merge
  with native analysis by cloud fingerprint (one canonical finding,
  many observations; PASS is evidence, never a finding); CloudMapper
  and ROADtools are defensive import connectors; **Pacu is registered
  DISABLED — classification CLOUD_OFFENSIVE_TESTING, no adapter, no
  execution path**. CIS AWS 1.5 / CIS Azure 2.1 / CIS GCP 1.6 control
  assessments reuse the Phase 13 compliance framework; snapshot diffs
  and conservative Checkov IaC↔live correlation produce drift;
  evidence-backed risk paths model exposure without ever executing
  it. A `/cloud-security` GUI (dashboard, accounts, resources, IAM,
  exposure, storage, graph) fronts the `/cloud/*` API. Migration
  `20261007110000_multi_cloud_security` generated, not applied
  (Docker unavailable on the build VM).
- **2026-10-07 — Prompt 13: Container, Docker & Kubernetes Security.**
  Container images became digest-bound inventory (`ContainerImage` +
  drift snapshots): registration parses references, scans resolve the
  digest in an `IMAGE_RESOLUTION` stage, and every finding binds to the
  digest it was found in. Analysis is static only — images are never
  executed, no Docker socket is mounted anywhere (a test asserts the
  compose file), and tools run NO_NETWORK on an isolated
  `CONTAINER_ANALYSIS` worker. Trivy (vuln/misconfig/secret kinds kept
  strictly separate; secrets are fingerprint-only), Syft (image SBOM
  inventories; CycloneDX built on demand), and the Prompt 12 Grype
  adapter extended to image inputs — the same CVE from Trivy+Grype on
  one digest correlates into a single canonical finding. Docker Bench
  and kube-bench are `INTERNAL_PRIVILEGED`: selected only for approved
  host/cluster targets and executor-refused unless the worker is a
  dedicated `PRIVILEGED_HOST`. The Kubernetes connector inventories
  clusters read-only from reference-registered connections (secret
  values are unobtainable through its transport), and the posture
  engine flags privileged workloads, hostPath, dangerous capabilities,
  root containers, RBAC excess, NetworkPolicy gaps and unpinned images;
  kube-hunter is passive-only by check classification, Kubescape and
  Checkov analyze manifests under hostile-YAML limits, and static vs
  live findings correlate by configuration fingerprint. CIS Docker /
  CIS Kubernetes / NSA-CISA control assessments are recorded as
  evidence (never certification), Falco events ingest through a
  sanitized trusted path as detections (never vulnerabilities), and the
  container quality gate fails on KEV image CVEs (governed dataset
  only), critical CVEs, image secrets and privileged containers.
  Migration `20261007100000_container_kubernetes` generated, not applied
  (no Docker on the build VM); verification is fixture-only — no image
  pulled, no cluster contacted.
- **2026-10-07 — Prompt 12: Source Code Security Engine.** Repositories
  became first-class `SOURCE_REPOSITORY` targets whose content is
  hostile input: SSRF-guarded git intake (reference-name credentials
  only), traversal/symlink/bomb-safe archive + snapshot manifests, and
  immutable content-hashed snapshots — analyzed read-only under a
  `DO_NOT_EXECUTE_SOURCE` policy (no builds, no lifecycle hooks, no git
  hooks; build-needing analysis reports `BUILD_REQUIRED`). Ten governed
  adapters: Semgrep (approved pack catalog per profile/language),
  CodeQL (no-build mode + hardened SARIF import), Bandit, Brakeman,
  SpotBugs (security findings only), SonarQube (connector; hotspots are
  REVIEW_REQUIRED, never auto-vulnerabilities), Gitleaks, TruffleHog
  (external verification pinned OFF), OWASP Dependency-Check (all
  network features off) and Grype. Secrets are metadata only — type,
  detector, file/line, one-way fingerprint, redacted preview; the raw
  value is dropped at parse time and exists in no table, event or API
  response (proven by fixture tests with fake secrets). SCA is
  lockfile-first across npm/pnpm/yarn, pip/Pipenv/Poetry, Maven/Gradle,
  Bundler, Go, Cargo and Composer; CVE matching runs ONLY against the
  Prompt 11 governed local dataset (empty ⇒ zero matches, honestly),
  links are POTENTIAL_EXPOSURE, fixed versions only from trusted data.
  Line-stable fingerprints merge the same flaw across tools and
  snapshots (NEW/EXISTING/RESOLVED baselines); CycloneDX/SPDX SBOMs are
  deterministic per snapshot; the quality gate records PASSED/FAILED/
  WARNING per scan. New `/code-security` GUI + repository detail
  (snapshot, findings, secret dashboard, dependencies, SBOM),
  `/repositories` API with the §98 permission set, migration
  `20261007090000_code_security` (generated, not applied — no Docker on
  the build VM). Fixture-verified end to end; tool binaries absent
  report UNAVAILABLE honestly.

- **2026-10-07 — Prompt 11: Vulnerability Management & Intelligence.**
  The management layer over findings: a full lifecycle state machine
  (NEW → TRIAGED → CONFIRMED → IN_PROGRESS → REMEDIATED → RETEST_PENDING
  → RESOLVED, plus FALSE_POSITIVE / ACCEPTED_RISK with mandatory reasons,
  approver + expiry for risk acceptance, and reopen-before-progress for
  false positives), assignment, sanitized comments, tenant-scoped tags,
  bulk actions and CSV/JSON export with formula-injection protection.
  Intelligence foundation: governed LOCAL CVE/CWE/CPE/EPSS/KEV dataset
  with pure fixture-tested providers (NVD / FIRST EPSS / CISA KEV), an
  incremental checksum sync engine with injected fetching (no fetcher
  wired in this build — sync states honestly read NEVER_SYNCED/FAILED,
  and enrichment attaches NOTHING when the dataset is empty), CVSS
  source-trust (§32), CPE → POTENTIAL_EXPOSURE correlation, and Risk
  Engine V2 (EPSS/KEV/exploit-reference factors, full explanations,
  P0–P4 remediation priority separate from severity, intelligence
  snapshot per calculation). Greenbone/OpenVAS + Nessus Professional
  connectors (administrator-mapped logical profiles, scope-derived
  targets only, hostile-input-hardened parsers, preview→commit report
  imports with scope quarantine), SearchSploit as REFERENCE LOOKUP ONLY
  (never exploit execution), SLA policies as data + computation,
  deterministic remediation grouping, FindingObservation records
  (one canonical vulnerability, many scanner observations), targeted
  retests executed by the worker through the same gates, /vulnerabilities
  + /remediation + CVE detail GUIs. No live feed was fetched and no
  scanner was contacted: everything is verified on recorded fixtures.


- **2026-10-07 — Prompt 10: Network VAPT Engine.** Eight network
  adapters (Nmap, Naabu, RustScan, Masscan, Netdiscover, arp-scan,
  tcpdump, tshark) on the SDK lifecycle with recorded-output fixtures
  (RFC 5737 ranges only — nothing was scanned). NetworkScope + CIDR
  canonicalization and a size policy (small = normal, large =
  elevated, very large = administrator, above the ceiling = denied);
  protected destinations (loopback, link-local/metadata, platform
  infrastructure) denied unconditionally, private ranges gated on an
  approved internal engagement; DNS revalidation immediately before
  execution. Bounded expansion persists NetworkScanChunk rows — never
  per-host rows for big ranges. Nmap plans are typed-config only;
  NSE scripts are governed by a classified catalog (SAFE /
  REVIEW_REQUIRED selectable, INTRUSIVE / DISABLED never — even when
  "approved"); XML output is parsed by a hardened reader (no DTD
  subsets or external entities, size/depth caps). Masscan is
  capability-isolated, approval-gated in the executor and
  hard-clamped (rate/targets/ports/duration). Local layer-2 discovery
  runs only on internal workers holding LOCAL_LAYER2_ACCESS
  (`UNAVAILABLE_FOR_WORKER` elsewhere, proven end-to-end). Services
  normalize with state, CPE (source-only), sanitized banners, TLS
  facts and confidence, and merge across scanners via the
  PortResultAggregator (one canonical row, provenance unioned, OPEN
  outranks CLOSED). Findings come only from the governed check policy:
  cleartext telnet/FTP, the unauthenticated Docker API on 2375/tcp,
  and script-confirmed SMB signing — databases and remote-admin
  services are exposure observations, and no login is ever attempted.
  Packet captures are metadata + object storage (PacketCaptureArtifact)
  with OWNER/ADMIN, audited raw access (RAW_PCAP_ACCESSED). New API
  surface under /network (+ §73 scan routes), a /network GUI with host
  detail, nine new audit actions, and worker types
  (GENERAL_WEB/NETWORK_EXTERNAL/NETWORK_INTERNAL/PACKET_ANALYSIS)
  driven by deployment env. Metasploit, brute force, spraying and
  exploitation remain explicitly unimplemented (§88). Migration
  `20261007070000_network_vapt` generated (not applied — no Docker on
  the build host).
- **2026-10-07 — Prompt 9: API Security Testing & Protection Assessment.**
  Guarded specification imports (OpenAPI/Swagger JSON+YAML, Postman
  collections + environments, Insomnia exports, GraphQL introspection)
  under hostile-input limits — 10 MiB caps, strict parsing, YAML
  unknown-tag rejection, external `$ref`s recorded as warnings and
  never fetched; secrets in collections/environments are dropped to
  reference NAMES during parsing. Imports yield INVENTORY ONLY (zero
  findings): ApiService / ApiSpecification / ApiSchema / GraphqlService
  records plus endpoint rows whose `{id}` path templates survive
  intact. An API operation policy classifies every operation SAFE /
  STATE_CHANGING / DESTRUCTIVE_UNKNOWN / REVIEW_REQUIRED (tighten-only
  admin overrides); Schemathesis runs only its safe check subset with
  non-SAFE operations excluded by name, methods pinned to
  GET,HEAD,OPTIONS, and the worker never enabling state-changing
  execution — blocked operations are counted and emitted as events.
  New adapters on the standard lifecycle: Kiterunner (governed
  API_ROUTES wordlists), Schemathesis (JUnit via the XXE-safe parser),
  InQL + GraphQLmap (introspection inventory — an observation, never a
  finding; mutations never executed), jwt_tool as a platform inspector
  (decode-only: fingerprint + redacted claims; no cracking, tokens
  never stored/logged/audited), and mitmproxy joining the connector
  family for flow/WebSocket traffic import (issues honestly empty —
  it has no scanner feed). The API_ASSESSMENT profile gains nine
  stages (API_DISCOVERY, SPEC_IMPORT, ROUTE_DISCOVERY, AUTH_MAPPING,
  SAFE_SCHEMA_TESTING, JWT_ANALYSIS, GRAPHQL_ANALYSIS,
  WEBSOCKET_INVENTORY, API_FINDING_NORMALIZATION) and flows into the
  Phase 7 normalization → correlation → risk tail; Nuclei gains two
  governed SAFE API templates. Authorization test cases exist as
  NOT_APPROVED design records (identity A/B contexts, object-id
  templates) — nothing executes them in this phase. GUI: API Security
  dashboard, per-service and per-endpoint views, GraphQL and JWT
  profile pages. Verified entirely against recorded fixtures with
  obviously-fake JWTs — no check ran against any real target; absent
  binaries report UNAVAILABLE and mitmproxy NOT_CONFIGURED. See
  `docs/architecture/api-security-engine.md`,
  `docs/security/api-operation-policy.md` and `docs/tools/api/`.
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
