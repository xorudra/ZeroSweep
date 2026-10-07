# AD Credential Model (Prompt 15 §7–§12)

## References, never values

A domain's assessment identity is a `DirectoryCredentialProfile` that
stores a **secret-reference name only** (e.g.
`vault:prod/ad/assessment-account`). The API refuses secret-shaped
values at the schema layer and again at the service boundary; no
endpoint accepts, stores, returns or logs a password, hash, ticket
or key. Scan events and findings carry ids and counts only (§113).

## Least privilege

Two identity kinds exist: `READ_ONLY_DOMAIN` (a standard domain user
with directory read — sufficient for inventory and posture) and
`APPROVED_DIRECTORY_AUDITOR` (read plus the audit rights an approved
engagement records). **Domain Admin is never requested** (§8): the
assessment is designed to work without it, and privileged-group
membership of the assessment account is itself reported by the
posture engine.

## Job-scoped leases

At scan time the `DIRECTORY_ANALYSIS` worker validates the domain and
issues a `CredentialLease` bound to the domain row: reference name,
purpose `DIRECTORY_ASSESSMENT`, TTL clamped to at most 3600 seconds
(§12). The lease is the audit record of credential use; the secret
value is resolved only inside the worker's secret resolver at
collection time and never persists. Hostile directory data cannot
smuggle credential material into storage: parsers strip
credential-shaped fields recursively before persistence, and a
dedicated test plants a password marker + NT-hash pair in a fixture
export and asserts they appear in no output (§113).
