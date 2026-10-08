# SOC Engine (Prompt 28)

The SOC layer (`apps/api/src/modules/soc/`) turns recorded platform
signals into coordinated security operations: telemetry ingestion,
declarative detections, deduped alerts, incidents with append-only
timelines and hash-anchored evidence, a governed response engine,
and SOC analytics. It layers over what already exists — the P24
event bus + outbox, the P27 data lake + correlation engine, the P22
notification router and the P23 identity stack — and adds no second
copy of any of them.

## Pipeline

```
telemetry ingest (scoped auth, §9)
  → canonical store (normalized, redacted, fingerprinted, §5–§13)
  → indicator matching (§64) → detection evaluation (§19–§24)
  → SOC correlation patterns (§71, over the P27 engine's data)
  → alerts (fingerprint dedupe, priority engine, §30–§35)
  → triage / suppression (§36–§40)
  → incidents + cases (§41–§53) → playbooks (§83–§89)
  → response actions (catalog + approval policy, §74–§82)
```

## Invariants

- **No synthetic operations data.** Alerts and incidents derive only
  from real platform records (ingested telemetry, findings,
  correlations). An empty workspace shows an empty SOC.
- **One alert path.** Every alert — detection, correlation,
  indicator match, manual — is raised through `AlertService`,
  which owns suppression checks, fingerprint dedupe and the
  priority engine.
- **Tenant isolation everywhere.** Every query is workspace-scoped;
  a foreign record id inside the caller's workspace returns 404.
- **Audit on every mutation** (§127 action set).
- **Honest unavailability.** Live intel transports and external
  notification channels report `NOT_CONFIGURED`; nothing is
  fabricated to fill the gap.
