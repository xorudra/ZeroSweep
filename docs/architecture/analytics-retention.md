# Analytics Retention (Prompt 27 §113–§116, §143)

Retention is per-workspace policy (`AnalyticsRetentionPolicy`; defaults:
events 730 d, snapshots 730 d, projections 365 d, search documents 365 d)
executed explicitly via `POST /analytics/retention/run` — there is no
hidden daemon.

## What retention may delete

Only **lake-owned** record kinds whose owning timestamp is past the
policy cutoff, and never RESTRICTED-classification events.

## What retention must never delete

- `AuditLog` — the audit trail is not analytics data (§114/§148).
- Operational records (findings, assets, scans…) — retention is not a
  data-management tool for the operational store.
- Anything in another workspace — every delete is workspace-scoped.

Projections and search documents are *derived*: deleting them loses
nothing, because they rebuild deterministically from landed events and
operational rows (see `docs/operations/analytics-rebuild.md`).
