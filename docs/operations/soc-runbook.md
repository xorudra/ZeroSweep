# SOC Runbook (Prompt 28 operations)

## Daily flow

1. **SOC dashboard** (`/soc`): check open P1/P2 alerts, active
   incidents, SLA breaches, and telemetry source health. A source
   in `GAP` state means a blind spot — treat it as an operational
   incident, not a statistic.
2. **Evaluation tick:** `POST /soc/evaluate` (or the dashboard
   button) opens/resolves telemetry gaps and flags SLA at-risk /
   breached alerts, emitting lake events once per alert. Run it on
   the same cadence as the P22 scheduler tick.
3. **Alert queue** (`/soc/alerts`): triage NEW alerts first by
   priority. Record a decision and a reason on every alert — the
   FP/TP rates drive detection health.
4. **Escalate** anything needing coordinated response; work the
   incident from its workspace page (timeline notes as you go —
   the timeline is the record).

## When something looks wrong

- **Alerts stopped appearing:** check telemetry health first
  (silent source?), then detection health (rule disabled/failing?),
  then suppressions (an over-broad suppression is scoped + expiring
  by construction, but check its scope and reason).
- **Duplicate alerts:** dedupe is by fingerprint; duplicates in the
  queue mean a rule was edited (new version = new fingerprint) or
  the group key differs (different asset/identity).
- **SIEM forwarding questions:** forwarding is queued through the
  P24 outbox — check delivery state there, not the SOC module.
- **Numbers look empty:** SOC analytics are computed from recorded
  rows only. Empty is a true answer for a quiet workspace.

## Honest limits in this environment

Live intel feed transports are NOT_CONFIGURED (imports are the
ingestion path); external notification channels beyond in-app are
recorded/queued, not delivered; MinIO object storage is
unprovisioned, so evidence is stored as hashed content/references
in the database, not as S3 objects.
