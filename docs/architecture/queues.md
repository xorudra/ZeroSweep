# Queue architecture

BullMQ over Redis. Queues (names in `@dsrclone/config`):
- `assessment-orchestration` — one job per scan; the worker expands it into
  stage/tool jobs in later phases. This phase: placeholder handler only.
- `dsrclone-placeholder` — harmless smoke-test job: log id, brief wait, complete.
- `report-generation`, `normalization` — reserved for later phases.

Rules: only safe TRANSIENT and TIMEOUT failures auto-retry (bounded, backoff);
policy/configuration/target errors never retry. Jobs carry identifiers
(organizationId, workspaceId, scanId), never secrets or raw commands.
