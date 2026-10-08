# Posture History (Prompt 22 §29–§32, §76–§80, §92)

Posture history is built from **immutable** `SecurityPostureSnapshot`
rows: asset/finding counts, severity and lifecycle distributions,
KEV count, verified findings, SLA overdue/due-soon, coverage, and a
risk score that is the mean of stored finding risk scores — `null`
when no scored findings exist, never an invented number.

Immutability (§32) is structural: the snapshot service exposes
create + read only. There is no update or delete path, so history
cannot be rewritten after the fact — the same contract as Prompt 20
report snapshots.

Rollups (§92) bucket snapshots hourly/daily/weekly taking the last
capture per bucket (`rollupPostureSnapshots`), served at
`GET /posture/rollups`.

## AI daily summary (§76/§77)

`AiDailySecuritySummary` is assembled from the day's stored records
only — the posture snapshot, surface changes, finding/risk drift and
schedule runs — and stores the **ids of the records it cites**. The
generator is labelled honestly: RULE_BASED in this deployment (no AI
provider is configured; Prompt 21 posture). The summary describes
posture; it has no execution surface and can never launch intrusive
scans (§75).
