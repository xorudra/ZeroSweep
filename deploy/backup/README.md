# Backup design (Prompt 25 §115–§127)

## PostgreSQL

- **Full backups**: daily `pg_dump` custom format via
  `backup-postgres.sh`, executed with a DEDICATED backup credential
  (separate from the application role; read-oriented), SHA-256 manifest
  alongside, optional `age` client-side encryption.
- **PITR (§116)**: on managed PostgreSQL, enable provider WAL archiving /
  continuous backup; the daily dump is the portable fallback. On
  self-hosted Postgres, archive WAL to the backup bucket with the same
  retention; restore = base backup + WAL replay to a timestamp, then the
  §126 verification checks.
- **Credentials**: backup tooling uses its own restricted credentials
  (§118) — never the application's, never an operator's personal account.

## Object storage

- Bucket mirror (`backup-objects.sh`) to a SEPARATE bucket/account with
  versioning enabled and **object-lock (WORM)** retention where the
  provider supports it (§120), so ransomware/deletion in the primary
  cannot rewrite history.

## Retention (example policy, §119)

| Class | Retention |
|---|---|
| Daily | 14 days |
| Weekly | 8 weeks |
| Monthly | 12 months |

Legal/compliance holds override expiry; lifecycle rules implement the
table, and expiry is logged.

## Verification (§123/§125/§126)

A backup is healthy ONLY when `restore-verify.sh` passes against it:
checksum → isolated restore → schema/migration-head → core tables →
sample tenant reads → tenant-isolation assertions. Automated on a
schedule; alerting on staleness/failure (monitoring rules).
