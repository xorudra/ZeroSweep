# Local stack — Docker-less development/verification environment

Provisions a REAL PostgreSQL + Redis on localhost WITHOUT Docker, plus
the API, worker, scheduler and AI service from this repo — used to prove
the platform end-to-end (Prompt 25's mandatory live-stack verification).

## What it does

- **PostgreSQL 16.2** via the `pgserver` pip package's bundled binaries,
  run as the unprivileged `nobody` user (PostgreSQL refuses to run as
  root) on port **54329**, data under `~/workspace/zerosweep-local-stack/pgdata`.
- **Redis 7.2.5** built from the official source tarball, on port 6379,
  AOF enabled, data under `~/workspace/zerosweep-local-stack/redisdata`.
- Applies **all Prisma migrations** (`prisma migrate deploy`) and the
  **seed**, then boots API (4000), worker, scheduler and AI (8000).
- MinIO is the only component not provisioned here: its release binary
  could not be fetched from either official channel in this environment
  (dl.min.io returned 410, GitHub release asset 404). The platform treats
  object storage as an OPTIONAL dependency and the health endpoint
  reports it `down` honestly; report/artifact flows that need S3 remain
  unverified in this environment.

## Usage

```sh
bash scripts/local-stack/start.sh          # provision + migrate + seed + boot
node scripts/local-stack/smoke.mjs         # 13-step end-to-end smoke
bash scripts/local-stack/resilience.sh     # executable resilience subset
bash scripts/local-stack/stop.sh           # stop app processes + services
```

State lives OUTSIDE the repo in `~/workspace/zerosweep-local-stack/`
(venv, pgdata, redis build/data, logs, smoke.env with a locally
generated JWT secret). Nothing there is committed.

## Smoke coverage (smoke.mjs)

health → register → login → create target (example.com fixture) →
MANUAL_APPROVAL verification by the org owner → scope → assessment →
approve → orchestrated scan (simulation adapters; real tool binaries
absent by design) → terminal state → findings summary → persistence.
