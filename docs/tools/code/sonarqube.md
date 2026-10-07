# SonarQube (connector)

**Adapter:** `SonarQubeAdapter`, slug `sonarqube`, capabilities `SAST`,
`CODE_PATTERN_ANALYSIS`, `SCAN_RESULT_IMPORT`. Risk: PASSIVE.
Deployment: admin-registered ScannerInstance (reference names only).

SonarQube is a **connector**, not a worker binary (§23): administrators
register an instance (endpoint + credential references only, never
URLs or secrets in the database), map repositories to project keys,
and the adapter pulls issue data over the instance API during the SAST
stage — the only stage it may execute in.

## Classification discipline (§27)

- `VULNERABILITY` issues → findings.
- Security **hotspots → REVIEW_REQUIRED** findings — visible, tracked,
  never auto-promoted to confirmed vulnerabilities.
- Code smells and non-security bugs are counted as skipped
  non-security issues; they never become vulnerabilities.

## Health

NOT_CONFIGURED when no enabled instance exists for the workspace —
the SAST stage then proceeds with the CLI engines only.
