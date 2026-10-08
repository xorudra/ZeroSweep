# RC1 Backup / Restore / DR exercise (Prompt 39 §255–§259)

Method (§256): the current reference-stack database was backed up,
restored into an **isolated** scratch database (never over the live
primary), and verified for counts, history, ordering and tenant
isolation before the scratch copy was dropped. Tools: `pg_dump` /
`pg_restore` (PostgreSQL 16.2) — the same binaries the platform's P38
backup service orchestrates (its checksum-gated wrapper was proven in
Phase 38; this exercise revalidates the end-to-end path for RC1).

## Measured results (this session, live reference stack)

| Step | Result |
| --- | --- |
| Backup (`pg_dump -Fc`) | 1.06 s, 1,479,145 bytes |
| Isolated restore (`pg_restore`) | 88.7 s |
| Users after restore | 67 = 67 source ✅ |
| Organizations | 67 = 67 ✅ |
| Workspaces | 67 = 67 ✅ |
| Findings | 31 = 31 ✅ |
| Finding history rows | 42 = 42 ✅ |
| Audit log rows | 833 = 833 ✅ |
| Scans | 26 = 26 ✅ |
| Security reports | 6 = 6 ✅ |
| Per-workspace finding distribution (§258) | identical (diff-clean) ✅ |

The restore-order discipline (§257) and isolated-restore rule hold:
verification happened on the copy; the live database was never the
restore target. Disaster-recovery scope beyond the database (object
storage) follows the P25/P38 runbooks (MinIO data directory is part
of the stack backup set).
