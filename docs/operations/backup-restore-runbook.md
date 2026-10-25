# Backup & Restore Runbook — ZeroSweep

Tooling: `deploy/backup/`. Architecture & retention: `deploy/backup/README.md`.

## What is backed up

| Data | Method | Cadence | Notes |
|---|---|---|---|
| PostgreSQL | `backup-postgres.sh` (pg_dump custom format + SHA-256 manifest, optional age encryption) | Daily full | PITR via WAL archiving on managed PG (§116) |
| Object storage | `backup-objects.sh` (bucket mirror) | Daily | Destination bucket: versioning + object-lock ON |
| Configuration | Git (manifests/configmaps) | Every change | Secrets are NOT in git — they live in the secret manager; see key recovery |
| Release state | `release-manifest.json` per release | Every release | Image digests, migration head, worker version |
| SOC state (Prompt 28 §159) | Included in the PostgreSQL backup | Daily full | The 27 SOC tables (`SocTelemetrySource`, `SecurityTelemetryEvent`, `DetectionRule` + `DetectionRuleVersion`, `DetectionMatch`, `SecurityAlert`, `AlertTriage`, `AlertSuppressionRule`, `SecurityIncident`, `IncidentLink`, `IncidentTimelineEntry`, `IncidentEvidence`, `IncidentEvidenceAccess`, `InvestigationCase`, `ThreatIntelSource`, `ThreatIndicator`, `IndicatorObservation`, `IndicatorMatch`, `ThreatIntelFeedSync`, `ResponseActionExecution`, `ResponseActionApproval`, `IncidentPlaybookRun`, `IncidentCommunication`, `PostIncidentReview`, `SocSlaConfig`, `TelemetryDataGap`, `SocIncidentReport`) ride the same pg_dump/PITR path — no separate SOC backup job exists or is needed. Restore verification should additionally spot-check: evidence content hashes verify, alert fingerprints are intact (dedupe continuity), and detection rule versions match their pinned matches. |

## The rule that matters (§123)

**An uploaded backup is not a healthy backup.** Health = the last
`restore-verify.sh` run passed against the newest artifact:
checksum → restore into an isolated database → migration-head check →
core-table reads → **tenant isolation check** (§172). The
`ZerosweepBackupStale` and `ZerosweepRestoreVerificationFailed` alerts fire
otherwise.

## Routine restore (drill or real)

1. Pick the artifact (`BACKUP_DEST` listing; verify the `.sha256` first).
2. `BACKUP_DEST=... RESTORE_ADMIN_URL=... sh deploy/backup/restore-verify.sh`
   — must end with `RESTORE_VERIFIED`.
3. For a REAL recovery, restore into a NEW database (never over the live
   one), point a staging API at it, run the smoke flow, and only then
   promote (connection-string switch) per the DR runbook.
4. For PITR: restore the base backup, replay WAL to the target timestamp
   on the managed-PG console/tooling, then run step 2's integrity checks
   against the result.

## Failure handling

- Checksum mismatch → artifact is corrupt: fall back to the previous
  artifact, alert security (possible tampering), preserve the bad artifact
  for forensics.
- Migration-head mismatch → the artifact predates/postdates the deployed
  code: deploy the matching release (release manifest) before serving.
- Tenant-isolation check failure → STOP. Do not serve the restore; escalate
  per the platform incident runbook.
