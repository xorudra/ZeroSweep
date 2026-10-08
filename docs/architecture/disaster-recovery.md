# Disaster Recovery (Prompt 38 §176–§184)

Extends Prompt 25's DR plan. Failure classes: instance loss, data
corruption, accidental deletion, region loss, ransomware. Recovery
order: identity/secrets → database → object storage → queues →
services → verification (migration state, health, smoke via
`/admin/platform`).

- Corruption/deletion recover from the latest *restore-tested* backup
  (§175) into an isolated database first (§173), validate (§174),
  then promote by operator decision — promotion is never automatic.
- Ransomware: backups are not modifiable by application credentials;
  restore uses a clean account path and rotated credentials.
- Every exercise is recorded (`PlatformDrExercise`) with measured
  RPO/RTO or an explicit NOT_MEASURED (§235). Targets without
  measurements are aspirations, labelled as such (§180).
