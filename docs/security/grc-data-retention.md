# GRC Data Retention (Prompt 26 §116–§118/§141)

## Retention policy

Each workspace carries a `GrcRetentionPolicy` (archive/delete after
configurable periods, `legalHold` flag). Under a legal hold, no
automatic retention action is permitted for the workspace's GRC
records. Purging is a governed administrative operation: it is
permission-gated (MANAGE_POLICIES), audited, and never silent —
retention **reports** (§117) list what would be archived or deleted
before any action.

## What retention never touches silently

- Audit logs (append-only, platform-governed separately).
- Issued report snapshots and audit packages: immutable for their
  retention window; deletion requires explicit policy + permission
  and leaves an audit tombstone.
- Evidence referenced by a COMPLETED assessment remains pinned by
  that assessment's snapshot model (§21/§125).

## Backup & restore

GRC export/restore bundles (GrcBackupService) carry frameworks,
controls, mappings, assessments, results, risks, policies and
evidence **with hashes**. Restore verifies the bundle hash before
any write, re-verifies every evidence hash, and refuses to restore
into a non-empty workspace without an explicit confirmation flag.
