# Mobile Version Lineage (Prompt 35 §104–§108)

Findings carry a cross-build fingerprint (Prompt 17): app +
artifact lineage + component/location + rule (§104). Comparing two
builds of one application creates an `ApplicationVersionLineage`
edge with one `MobileFindingCarryForward` row per issue:

- **NEW** — present only in the newer build.
- **PERSISTING** — present in both.
- **FIXED_CANDIDATE** — present only in the older build. This is a
  hypothesis, never a fix: §108 — a new version does not
  automatically mean old findings are fixed. The comparison NEVER
  mutates the original finding.
- **REGRESSED** — absent in an intermediate build (or verified
  closed) and present again (§157); the row links back to the
  Prompt 31 regression machinery.

## Verification (§107/§156)

A FIXED_CANDIDATE is verified through Prompt 31: a targeted retest
of the same rule against the NEW build (`planMobileRetest`), then
verified closure only if the verification policy is satisfied.
`POST /api/v1/mobile/apps/:id/compare` returns each candidate with
its retest plan so the loop is one click, not a research project.

## Backup/restore (§162)

Lineage edges, carry-forward rows, plans and coverage snapshots are
ordinary Postgres rows covered by the platform backup. Large
artifact bytes remain in object storage; metadata, hashes, finding
history, SBOM references and verification history restore with the
database.
