# MobSF Integration (Prompt 35 §17–§19)

- MobSF is an admin-registered connector (Prompt 17): instance URL
  + API key as a secret REFERENCE. Keys are never logged (§18) and
  never appear in findings, plans or reports.
- The adapter supports artifact upload, scan start, status, static
  findings, certificate + manifest metadata, permissions, network
  observations, code findings and a report reference (§17).
- Result normalization (§19): informational observations are NOT
  promoted to vulnerabilities. Every result maps severity,
  confidence, category, evidence and CWE / OWASP MASVS where
  applicable, then enters the canonical correlation tail — a
  MobSF + JADX agreement on one issue is ONE canonical finding
  with multiple observations (§109/§158).
- Health is honest: an unregistered instance reports
  NOT_CONFIGURED; the pipeline continues without it.
