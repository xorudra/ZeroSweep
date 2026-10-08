# Runbook: DefectDojo (and peer) Sync (Prompt 37 §49–§59)

- Configure the integration with a credential **reference** only.
- Modes: PUSH (send our mapped payload; the job records it as
  payload-only — no live transport is wired), PULL (consume an
  exported payload from the external system), BIDIRECTIONAL_METADATA
  (both, metadata effects only).
- After each PULL, review `GET /vulnerability-integrations/sync-conflicts`:
  conflicts mean both sides changed the same field since the last
  sync. Resolve in DSRclone (canonical) or accept the external
  severity under the TAKE_EXTERNAL_METADATA policy on a later run —
  status never auto-applies.
- Echo safety: re-running the same PULL is idempotent; our own
  pushed content returns as SKIPPED_ECHO, and re-importing the same
  records dedups onto canonical findings as observations.
- Faraday follows the same procedure (§50); Dradis (§53) and
  PlexTrac (§54) payloads map through the same record shape
  (externalId, title, severity, status, cve).
