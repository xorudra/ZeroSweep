# Orchestration Engine (Prompt 4)

The orchestration engine turns an **authorized assessment** into a controlled
execution pipeline. The API plans and queues; workers execute. No security
tool runs in the API process, and no client can define tool commands.

```
Assessment → Authorization Gate → Scope Gate → ScanPlan (DAG) → Queue
→ Worker DagRunner → Stage Jobs (IDs only) → Adapter (mock/echo this phase)
→ Raw Artifact (object storage) → Parse → Normalize → Persist
→ Correlation → Risk → Report Preparation (REPORT_PENDING)
```

## ScanPlan

Built by `buildScanPlan` (`@dsrclone/orchestration`) and persisted immutably
on `ScanPlan` (plan JSON + policy snapshot). It records: scan/assessment/
target ids, profile, target type, scope rules, stages with dependencies,
selected adapters (with simulation flags), policy snapshot and plan version.
State and progress live on `Scan`/`ScanStage` — the plan document never
mutates after execution starts.

## DAG

Profiles resolve to stage templates (`PROFILE_TEMPLATES`): PASSIVE_RECON and
WEB_BASELINE are fully exercised this phase; other profiles are validated
templates. `buildDag` validates before anything is queued: **no cycles, all
dependencies exist, no duplicate stage ids, required stages present**
(AUTHORIZATION_CHECK, SCOPE_VALIDATION). Kahn layering identifies stages that
may run concurrently (e.g. TECHNOLOGY_DETECTION ∥ CRAWLING after
HTTP_DISCOVERY). `readyStages` readies a stage only when every dependency is
COMPLETED/PARTIAL/SKIPPED.

## State machines

- **Scan** (`@dsrclone/types`): CREATED → QUEUED → PREPARING → RUNNING →
  COMPLETED/PARTIAL/FAILED, with PAUSING → PAUSED (resume re-enters the
  queue) and CANCELLING → CANCELLED. Terminal states never leave.
- **Stage**: PENDING → BLOCKED → READY → QUEUED → RUNNING →
  COMPLETED/PARTIAL/FAILED/SKIPPED/CANCELLED. Dependencies drive
  BLOCKED → READY.
- **ToolExecution**: QUEUED → PREPARING → RUNNING → PARSING → NORMALIZING →
  COMPLETED, plus FAILED / TIMED_OUT / CANCELLING → CANCELLED.

Stage failure resolves through its **failure strategy**: FAIL_SCAN (scan
fails, remaining stages skipped), SKIP_DEPENDENTS (transitive dependents
skipped), FAIL_STAGE_CONTINUE / CONTINUE_WITH_PARTIAL_DATA (stage recorded
PARTIAL, dependents proceed, scan ends PARTIAL).

## Tool selection

`selectAdaptersForStage` chooses by required capability, target
compatibility, enabled status, health, risk level and policy — never merely
because a tool is installed. Only adapters on the phase's executable allowlist
(`mock`, `local-echo`) can be selected for execution; catalog tools are
rejected with an explicit reason. When no executable adapter covers a stage,
the Mock simulation adapter is selected and flagged `simulation: true` in the
plan, the API and the GUI. RESTRICTED adapters are never auto-selected.
Preferences (PRIMARY/SECONDARY/FALLBACK) are configuration, not code.

## Policy & scope gates

Two gates, evaluated **twice**: at plan/start time in the API and again in
the worker immediately before every execution, using state reloaded from the
database (never the queue payload):

1. **Authorization gate** — target exists, belongs to the workspace/org,
   ownership VERIFIED, assessment APPROVED, scope valid.
2. **Scope gate** — target host is inside the persisted scope
   (`ScopeMatcher`). Discovered assets are scope-checked individually;
   OUT_OF_SCOPE assets are recorded for visibility and **never** become scan
   targets automatically.

Per-adapter policy (Prompt 3 `evaluateToolPolicy`) runs in the worker on top
of both gates. Denials persist an audit record (POLICY_DENIED /
SCOPE_VIOLATION) and a durable event; the adapter never runs.

## Queues & payload security

BullMQ queues: `scan-orchestration`, `stage-execution`, `tool-execution`,
`result-processing`, `normalization`, `correlation`, `risk-analysis`,
`report-generation` (names in `@dsrclone/config`). Jobs carry **IDs only**
(scanId, stageId, toolExecutionId, attempt) — never credentials, tokens or
scanner output. BullMQ job ids are the deterministic idempotency key
`scanId:stageId:attempt`, and `ToolExecution.idempotencyKey` is unique in the
database, so duplicate delivery cannot execute a stage twice.

## Progress

Weighted stage progress (Prompt 4 §39): each profile assigns stage weights;
scan progress is the weight-weighted completion fraction (RUNNING = ½),
persisted monotonically — it never moves backward and never derives from
elapsed time.

## Events

Lifecycle events are **durable first**: persisted to `ScanEvent` (timeline
API `GET /scans/:id/events`, paginated) and then presented live over SSE
(`GET /scans/:id/stream`). The stream authorizes the scan against the
caller's workspace **before** subscribing — a foreign scan id is a 404, so no
cross-tenant event can leak. Event payloads carry safe metadata only.

## Cancellation, pause, timeouts, retries

- **Cancel** (idempotent): scan → CANCELLING, pending stages cancelled,
  running mock executions observe CANCELLED cooperatively (chunked delay,
  ~25ms), scan → CANCELLED with a `scan.cancelled` event. Emergency stop is
  the same converging flow with an audit marker.
- **Pause**: stops scheduling new stages; running mocks are not frozen
  mid-flight. **Resume re-evaluates authorization + scope + policy** before
  re-queueing.
- **Timeouts**: tool/stage/scan levels; a timeout produces TIMED_OUT state +
  structured event — a scan never sticks in RUNNING.
- **Retries**: only TRANSIENT and PARSER failures, bounded (3 attempts,
  exponential backoff). Policy/scope/target failures never retry. Exhausted
  jobs land in `DeadLetterJob` (admin-visible metadata, no sensitive payload).

## Artifacts & results

Raw adapter output is written to object storage (`scans/:scanId/executions/
:executionId/raw.json`) with SHA-256 checksum + size recorded on the
execution; only the normalized result is persisted to Postgres (assets with
scope verdicts, services, endpoints, technologies, findings with provenance
— scan, stage, tool, execution, fingerprint, and `isMock` for fixtures).
Correlation groups deterministically by fingerprint; risk scoring is
deterministic severity weighting this phase (no fabricated threat intel).
A completed pipeline creates a PENDING report row (REPORT_PENDING); the PDF
engine is a later phase.

## Recovery

`reconcileStaleExecution` decides per orphaned execution on worker startup:
completed work is left alone, never-started work is requeued, work on a live
worker is left alone, timed-out work is MARK_TIMED_OUT, orphaned running work
is MARK_FAILED honestly. Heartbeat staleness uses thresholds (30s degraded /
90s offline defaults) — one missed beat never offlines a worker.

## Admin visibility

`GET /api/v1/admin/orchestration` (OWNER/ADMIN only): worker nodes, recent
dead-letter jobs, stale scans, running/queued counts.
