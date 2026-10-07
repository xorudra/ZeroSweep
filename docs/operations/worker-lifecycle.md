# Worker Lifecycle (Prompt 4 §20–§23, §51–§52)

## Startup

1. Build the adapter registry — in this phase ONLY `MockSecurityAdapter` and
   `LocalEchoAdapter`. Real scanners are added by later prompts and must join
   the executable allowlist deliberately.
2. Register a `WorkerNode` row (`worker-<hostname>-<pid>`, version,
   advertised capabilities, status derived from heartbeat age).
3. Run **startup recovery** (`recoverStaleExecutions`): reconcile executions
   left mid-flight by a previous process — completed work is never re-run;
   never-started work is requeued; orphaned running work is marked FAILED or
   TIMED_OUT (see `docs/architecture/orchestration-engine.md`).
4. Connect BullMQ consumers: placeholder, `scan-orchestration` (+ legacy
   placeholder queue, acknowledged without executing), `stage-execution`
   (concurrency 4).

## Registration & capabilities

Workers advertise capabilities (this phase: the recon/web capability set the
simulation adapters cover). A worker must only be dispatched stages whose
required capabilities it advertises (`workerCanRun`) — e.g. no APK analysis
to a worker without mobile support (later phases).

## Heartbeat

Every 15s the worker upserts its `WorkerNode` (lastHeartbeat, derived status,
activeJobs) and writes the local health file. Status thresholds are
configurable (defaults: >30s stale = DEGRADED, >90s = OFFLINE) — a single
missed heartbeat never marks a worker offline.

## Job handling

For each `stage-execution` job (IDs only):

1. Load the ToolExecution + plan + target + scope from Postgres (trusted
   state — the payload is never trusted).
2. Idempotency: a COMPLETED execution returns immediately.
3. Re-evaluate authorization gate, scope gate and per-tool policy. Denial →
   FAILED execution + `policy.denied`/`scope.violation` event; the adapter
   never runs.
4. Run the adapter lifecycle (validate → plan → execute → parse → normalize)
   under the stage timeout with cooperative cancellation.
5. Store the raw artifact in object storage (checksum recorded), persist the
   normalized result transactionally, emit lifecycle events.
6. Failures are classified; only transient/parser failures are retryable —
   the rest terminate the execution and record a dead-letter entry.

Scan-orchestration jobs run the `DagRunner`: it walks the persisted DAG,
completes platform stages (authorization, scope, normalization, correlation,
risk, report preparation) as engine checks, dispatches tool stages, applies
failure strategies, and keeps scan progress monotonic.

## Draining & shutdown

On SIGTERM/SIGINT the worker:

1. Sets its WorkerNode status to DRAINING and stops accepting new jobs
   (handlers throw a retryable error if a job slips through).
2. Waits (≤30s) for active jobs to finish.
3. Closes BullMQ workers, disconnects Redis, logs the metrics snapshot
   (scans queued, durations, failures, timeouts, cancellations — labels never
   contain target values or credentials).
