# Single-Node Deployment (Prompt 38 §3, §205/§206)

1. Copy `deploy/examples/single-node.env.example` values into
   `deploy/compose/.env.production` (outside git) and replace every
   placeholder via your secret store.
2. `docker compose -f deploy/compose/docker-compose.production.yml up -d`
   — migrations run once via the migrate service before the API.
3. Verify: `curl https://<host>/api/v1/health` → all checks ok;
   sign in and open `/admin/platform` — config validation must show
   zero violations.
4. Optional observability: add `--profile observability`.
5. Run the first backup + restore test from `/admin/platform/backups`
   before onboarding tenants (§175).

Single-node limits are honest: no HA, backups are the recovery story;
see `capacity-planning.md` for when to move to Kubernetes.
