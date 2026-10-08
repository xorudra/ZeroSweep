# EASM Runbook

## Daily operations

1. Review the **Unknown Assets** queue; confirm, assign, or declare
   third-party. Nothing unknown is ever scanned.
2. Review **Exposure Drift** (CRITICAL/HIGH first); acknowledge with
   intent or let repeat sightings confirm.
3. Check **Certificates** for URGENT/EXPIRED and renew.
4. Confirm the last scheduled runs completed; a `PARTIAL` run means
   a source failed or is `NOT_CONFIGURED` — see
   `easm-tool-health.md` before re-running.

## Running discovery manually

`POST /easm/programs/:id/discover` (permission `RUN_EASM_DISCOVERY`).
Programs must be ACTIVE or DRAFT. Recorded source payloads may be
submitted per source; unselected sources are recorded
`SKIPPED_POLICY`.

## Promoting an asset

Verify the root first (challenge workflow), confirm candidate
ownership evidence, then promote. Promotion yields an UNVERIFIED
target in `PENDING_REVIEW` — complete the standard target
verification + assessment approval before any scan.

## Retention (§122)

| Record | Retention |
|---|---|
| Discovery observations | 180 days |
| DNS snapshots | 365 days |
| Certificates | retained while observed + 365 days |
| Screenshots (metadata) | 90 days |
| Drift events | 365 days |
| Baselines / report snapshots | indefinite (immutable) |
| Audit events | platform policy |

Retention enforcement is an operator-run maintenance task; the
platform never silently deletes evidence.

## Backup & restore (§151)

EASM data is Postgres-only (plus content hashes for baselines and
reports). Restore: restore the platform database, run
`prisma migrate deploy`, verify `/easm/dashboard` counts against the
pre-backup report snapshot hashes.
