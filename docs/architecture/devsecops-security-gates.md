# DevSecOps Security Gates (Prompt 24 §18–§45)

## Diff-aware assessments (§19)
A PR/MR assessment compares the scan's findings against the
repository's latest `SecurityBaseline` — an immutable fingerprint set
bound to a commit + snapshot (§41), never a branch name. Findings are
classified `NEW`, `PRE_EXISTING` or `REGRESSED` (a previously
resolved fingerprint that reappears, §122); baseline fingerprints
absent now are `RESOLVED`. Pre-existing risk stays visible in the
repository view but never fails a PR gate by itself (§121).

## Quality gate engine (§36–§39)
`SecurityQualityGateEngine` (SDK) evaluates TYPED rules only:
`maxNewCritical`, `maxNewHigh`, `blockNewKEV`,
`blockVerifiedCritical`, `blockNewVerifiedSeverity`,
`blockNewSecrets`, `blockPolicyViolations`, `minimumScanCoverage`,
`requiredScanners`. Unknown rule kinds are rejected at policy-write
time — a gate policy is data, never code. PR presets (§20) expand to
these rules. Scanner failure behavior is policy: `FAIL_CLOSED`
(default), `WARN`, `FAIL_OPEN` (§39/§123). Every evaluation is stored
with rule-level results, so a verdict is explainable after the fact.

## CI/CD (§32–§35)
Pipelines authenticate with service-account API keys carrying only
`pipelines:security-scan` / `pipelines:gate-read`. A run requests a
scan through the same governed trigger as webhooks (VERIFIED target +
pre-existing APPROVED assessment + fresh-DNS scope revalidation). A
webhook or pipeline can never approve an assessment (§136).

## What pipelines receive (§42)
Counts, finding IDs and redacted repository-relative locations —
never a secret value. Secret findings return the finding id, file,
line, severity and remediation guidance. SARIF 2.1.0 exports (§43)
are scrubbed by the same redaction boundary.
