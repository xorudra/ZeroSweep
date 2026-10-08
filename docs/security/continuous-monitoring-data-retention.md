# Continuous Monitoring Data Retention (Prompt 22 §91)

Retention is policy, reported honestly at `GET /monitoring/retention`
together with the current per-workspace footprint. Deletion is an
operator maintenance job; no read path deletes anything.

| Data | Retention | Notes |
| --- | --- | --- |
| Posture snapshots (+ asset/finding snapshot rows) | 13 months | Immutable while retained (§32) — retention expiry is the only removal path |
| Schedule runs | 12 months | Includes BLOCKED/SKIPPED outcomes — the audit trail of refused automation |
| Drift events + attack-surface changes | 13 months | Aligned with posture history |
| Notifications | 6 months | Includes suppression records |
| Workflow executions | 12 months | Includes BLOCKED_LOOP records |
| AI daily summaries | 13 months | Citations reference snapshot ids; a summary may outlive nothing it cites by design of the aligned windows |
| Scheduler leases | transient | Single row per scope; overwritten each tick |
| Dead-letter jobs | 12 months | Operator-reviewed |

Data minimization notes:

- Snapshot entries store normalized state (ports, services, counts,
  hashes) — never raw tool output, banners or evidence payloads.
- Notification records store titles/details produced from stored
  records; webhook signing secrets are references only, and no
  credential material of any kind is written by this module.
- Wireless-derived drift reuses Prompt 19 pseudonymized station
  identifiers; monitoring never de-pseudonymizes them.
- Audit metadata for this module carries ids, counts and reason
  codes only (§88).
