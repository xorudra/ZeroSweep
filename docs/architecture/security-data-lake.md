# Security Data Lake (Prompt 27)

DSRclone's analytics plane is a **logical data lake over PostgreSQL** — the
same governed store as the operational platform, with lake-owned tables that
are append-only, tenant-scoped and rebuildable.

## Landed records

| Table | Contents |
|---|---|
| `SecurityAnalyticsEvent` | Canonical append-only event stream. `eventId` is globally unique — it is the idempotency key (§9/§131). SHA-256 checksum over the canonical event JSON (§15). |
| `AnalyticsIngestionCheckpoint` | Per (workspace, consumer, partition) cursor + counters (§10). |
| `AnalyticsDeadLetterEvent` | Quarantined invalid events with machine-readable validation codes and a sanitized summary — never raw bodies (§11). |
| `FindingLifecycleProjection` | Per-finding lifecycle projection (first/verified/resolved/reopened, MTTR seconds, regression count). Pure function of landed events (§14/§133). |
| `RiskHistoryProjection` | Risk-score history points, deduped by `sourceEventId`. |
| `ExposureSnapshot` / `AssetSecuritySnapshot` | Point-in-time attack-surface and per-asset state for growth/drift analytics. |
| `SecuritySearchDocument` | Redacted enterprise-search index documents (§19). |
| `AnalyticsDashboardSnapshot` | Scheduled dashboard snapshots. |

## Invariants

- **Append-only landing.** Events are never updated in place; corrections
  arrive as new events. Projections are derived and may be deleted and
  rebuilt at any time (§117).
- **Tenant context is part of validity.** An event whose
  organization/workspace does not match the consuming scope is rejected to
  the dead-letter (`TENANT_CONTEXT_MISMATCH`), never re-homed (§12/§148).
- **Redaction before landing in derived stores.** Search documents and
  snapshots pass the platform redactor; secrets appear nowhere (§111/§130).
- **Audit records are not lake data.** `AuditLog` is never deleted by
  analytics retention (§114/§148).

## Layout & partitioning path (§17)

The event table is indexed on `(organizationId, workspaceId, eventTime)`,
`(workspaceId, findingId, eventTime)`, `(workspaceId, eventType, eventTime)`
and related facet columns. Declarative range partitioning by `eventTime`
is the documented scale-out path: it is intentionally **not** applied via
raw SQL migrations, because hand-partitioned tables fight Prisma schema
drift; when event volume justifies it, partitioning is introduced as an
operations change with a drift-checked migration, and every query in the
analytics layer already constrains `eventTime` ranges so partition pruning
applies unchanged.
