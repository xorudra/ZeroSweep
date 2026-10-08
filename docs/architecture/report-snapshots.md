# Report Snapshots & Versions (Prompt 37 §63/§64/§83)

Two freeze points protect report integrity:

1. **ReportSnapshot** (Prompt 20): built once from stored findings at
   generation time, content-hashed, redacted at build. Regeneration
   of an ISSUED report is refused.
2. **ReportVersion** (Prompt 37): at finalization the snapshot
   document is copied into a version row together with the
   snapshot's content hash and the SHA-256 of the rendered artifact.
   No code path updates a ReportVersion after creation.

Consequences, all test-pinned (§140–§142):

- Editing a finding after finalization cannot change the version's
  document or any rendering of it.
- Report facts (counts, severities, CVE references) come from the
  frozen document; the AI draft fact-checker validates against it.
- Trends never read live state: executive trends come from stored
  `VulnerabilityMetricsSnapshot` rows only (§75).
