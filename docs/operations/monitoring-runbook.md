# Monitoring Runbook (Prompt 38 §120–§123, §236–§239)

- Dashboards: `deploy/monitoring/dashboards/` (ten §118 boards).
  "No data" means the exporter for that series is not running —
  treat it as a monitoring gap, not as zero.
- Alerts group/inhibit in Alertmanager so one root failure pages
  once. Triage order: dependency down → migration state → queues →
  workers → error budget.
- Error budget: SLOs are computed in `/admin/platform` from measured
  records. When budget burns fast, freeze releases (§126) — the
  checklist in `production-readiness-checklist.md` gates go-live.
- Daily (§236): health panel + backup status. Weekly (§237): restore
  test result + SLO table. Monthly (§238): capacity review.
  Quarterly (§239): DR exercise + access review.
