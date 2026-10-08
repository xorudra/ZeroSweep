# DSRclone deployment (Prompt 25)

## Canonical path (§24–§26)

**Kustomize is canonical**: `kubernetes/base` + `kubernetes/overlays/{development,staging,production}`.
Helm (`helm/dsrclone`) is an equivalent-subset alternative for Helm-native
shops. Production Compose (`compose/docker-compose.production.yml`) covers
single-host deployments. All three express the SAME topology and security
posture; if they ever disagree, the Kustomize base + `deploy/policies`
win, and the divergence is a bug.

## Topology

```
Internet ── Ingress (HTTPS only) ──► web (stateless, HPA)
                                  └─► api (stateless, HPA) ──► PostgreSQL (state)
                                          │                     Redis (queues, IDs only)
                                          ├──► ai (optional)    Object storage (artifacts)
                                          └──► scheduler (1 replica, DB lease)
Queues ──► worker pools (per ScannerCapabilityPolicy) ──► scan Jobs (isolated, per stage)
Migration Job (one-shot per release) ──► PostgreSQL DDL (only DDL path)
```

Separate concerns (§27–§29): **configuration** (ConfigMap / env, in git),
**secrets** (secret manager → `dsrclone-secrets`, never in git), and
**state** (PostgreSQL, Redis AOF, object bucket) evolve and rotate
independently.

## Secret rotation tolerance (§31)

| Secret | Rotation effect | Procedure |
|---|---|---|
| JWT_SECRET | Existing tokens expire within JWT TTL | Update secret → rolling restart API |
| DATABASE_URL password | Old role password revoked after overlap window | Create new password → update secret → rolling restart api/workers/scheduler → revoke old |
| REDIS_URL password | Brief queue reconnects | Update secret → rolling restart |
| Object-storage keys | Downloads retry once | Update secret → rolling restart workers/api |
| TLS certificate | None | Replace ingress secret → ingress reload |
| Backup credentials | Next backup uses new creds | Update backup job secret only |

## Cost controls (§176)

- HPAs are bounded; scanner pools scale on queue signals and scale down
  aggressively (long stabilization windows prevent flapping).
- Ephemeral-storage limits stop runaway scan artifacts; artifact
  lifecycle rules expire raw evidence per retention policy.
- The AI service is a single small replica; it is advisory and optional.
- No always-on staging scanner pool (staging overlay ships
  worker-network at 0 replicas).

## Environments (§32)

`development` (permissive defaults), `test`, `staging` (production rules,
synthetic/minimized data), `production` (fail-fast config gate, hardened
defaults). Staging NEVER holds a copy of production tenant data.
