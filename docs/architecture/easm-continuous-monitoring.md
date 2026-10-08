# EASM Continuous Monitoring

Continuous EASM rides the Prompt 22 scheduler — no separate daemon,
no hidden timers.

- Each monitoring-enabled program gets a `SecuritySchedule` row with
  `kind = "EASM_DISCOVERY"`, visible in the existing scheduler UI.
- `POST /easm/monitoring/tick` (operator-invoked, permission
  `RUN_EASM_DISCOVERY`) materializes due programs into discovery
  runs with trigger `SCHEDULED`, advancing `nextRunAt` by tier.
- **Tiers**: `HOURLY_LIGHT` restricts sources to DNS resolution,
  DNS zone observation, certificate transparency, TLS handshake, and
  HTTP probe. `DAILY` and `WEEKLY_DEEP` use the program's full
  policy. Expensive adapters never run hourly.
- The tick uses a system actor (`system:easm-scheduler`) but every
  internal gate still applies — a scheduled run can never authorize
  active testing, approve scope, or scan anything. Discovery-class
  only, per the P22 safety classes.
- Retention (§122, operational defaults recorded on baselines and
  runbooks): observations 180d, DNS snapshots 365d, screenshots 90d,
  drift events 365d, audit per platform policy. Retention jobs are
  operator-run; nothing is silently deleted.
- Backup/restore (§151): EASM state is ordinary Postgres data plus
  content-hashed baselines/reports; restore = platform DB restore +
  `prisma migrate deploy`. Drift history and baselines survive
  because they are append-only rows, not caches.
