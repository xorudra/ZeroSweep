# Capacity Planning (Prompt 38 §84/§85, §241)

Measured inputs only: queue waiting/active by class, worker busy
slots, DB pool usage, storage growth of artifacts/reports, scan
duration percentiles (dashboards). Rules:

- **Database connections:** pool-per-replica × replicas + 10 headroom
  ≤ `DB_CONNECTION_BUDGET` (default 100). The production config gate
  computes this at boot (§27); raise the budget only with a database
  that can serve it.
- **Workers:** add pool replicas when oldest-waiting age grows while
  CPU < 70% (queue-bound) vs CPU-bound pools needing faster nodes.
- **Storage:** artifacts dominate; retention is governed by report/
  artifact retention policies (Prompt 20/37), not by disk panic.
- Review monthly (§238) and record the numbers used — capacity claims
  without measurements are not made here either.
