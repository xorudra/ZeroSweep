# Secret Scanning (Prompt 12 §36–§44)

Gitleaks and TruffleHog scan the snapshot (bounded history depth from
the scan budget, §83) for committed credentials. The platform's contract
is absolute: **a secret value is never stored, displayed, logged or
exported — anywhere.**

## How the guarantee is built

- Parsers consume the matched value exactly once: it feeds the
  **SecretFingerprintService** (HMAC-SHA256 when a key is configured,
  domain-separated SHA-256 otherwise) and the **redacted preview**
  builder (first/last fragments, only for values long enough that the
  fragments cannot reveal them — e.g. `AKIA…MPLE`). The value is then
  dropped; no downstream type has a field that could hold it.
- Persisted shape is `SecretFindingMetadata` only: secret type
  (API_KEY / TOKEN / PRIVATE_KEY / PASSWORD / DATABASE_CREDENTIAL /
  CLOUD_CREDENTIAL / CERTIFICATE_SECRET / GENERIC_SECRET), detector,
  file, line, commit, fingerprint, redacted preview, verification
  status, lifecycle status. The Prisma model has no value column.
- Evidence snippets pass through the redactor; worker events carry
  counts and types only; audit metadata never contains values (§110).
- Tests embed obviously-fake secrets in fixture outputs and assert the
  raw strings appear in **no** persisted row, event, API response or
  log line (§101).

## Verification posture (§37/§44)

TruffleHog's external verification is **disabled by default and never
enabled by the worker** (`--no-verification` is pinned in the plan; a
configuration requesting external verification is rejected). A finding's
verification status therefore stays `NOT_VERIFIED` unless an
administrator-governed process changes it — the platform does not probe
third-party services with discovered credentials.

## Lifecycle (§43)

`OPEN → ROTATION_REQUIRED → ROTATED`, with `FALSE_POSITIVE`,
`ACCEPTED_RISK` and `RESOLVED` exits — managed from the secret dashboard
(§93) under `VIEW_SECRET_METADATA` / repository-management permissions,
and audited. Cross-tool duplicates (the same secret found by both
scanners) merge into one canonical finding whose fingerprint is derived
from the secret fingerprint, so rotation tracking follows the secret,
not the tool.
