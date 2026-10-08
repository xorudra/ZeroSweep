# Analytics Rebuild & Backup Note (Prompt 27 §117/§146)

## Rebuild

Projections are pure functions of landed events:

- `POST /analytics/projections/rebuild` deletes nothing; it replays each
  finding's landed event timeline through `projectFindingLifecycle` and
  upserts `FindingLifecycleProjection` + `RiskHistoryProjection`.
  Rebuild output is deterministic — the same events always produce the
  same projection (§133 test).
- Full recovery sequence after data loss in derived stores:
  1. `POST /analytics/ingestion/run` (re-consume outbox + finding history
     from checkpoints; landing is idempotent on `eventId`).
  2. `POST /analytics/projections/rebuild`.
  3. `POST /analytics/reindex`.
  4. `POST /analytics/correlations/run`, `POST /analytics/attack-paths/generate`.

## Backup (§146)

The lake's source of truth is (a) the operational tables and (b) the
landed `SecurityAnalyticsEvent` stream. Backing up PostgreSQL (Prompt 25
backup/DR runbooks) therefore backs up everything needed: projections,
snapshots-derived analytics, search documents, signals and attack paths
are all rebuildable from those two sources with the sequence above.
Derived tables may be excluded from *restore priority* but are included
in the standard backup for restore speed.
