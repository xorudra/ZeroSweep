# Cloud Inventory & Snapshots (Prompt 34 §15–§18)

Inventory discovers accounts/subscriptions/projects, regions,
resources, identities, relationships, tags and criticality through
the Prompt 14 read-only connectors. Collected resources are never
modified — encryption, logging and access changes happen only
through the governed remediation workflow as plans.

## Resource snapshots (§17)

Every assessment stores an immutable `CloudResourceSnapshot` per
resource: a canonical-JSON configuration snapshot with a SHA-256
hash. Building a snapshot strips secret-shaped KEYS entirely and
redacts secret-shaped VALUES (provider key patterns, token markers)
before hashing — a snapshot can therefore never contain a credential,
and the fact is proven by test (a fixture canary key is stripped).

## Drift (§18)

Consecutive snapshots are diffed field-by-field into drift events:
PUBLIC_EXPOSURE (severity ELEVATED when a resource becomes PUBLIC),
SECURITY_GROUP_CHANGE, IAM_CHANGE, ENCRYPTION_CHANGE,
LOGGING_DISABLED / LOGGING_CHANGE, CONFIGURATION_CHANGE; set-level
diffs add RESOURCE_ADDED / RESOURCE_REMOVED. Drift events persist to
`CloudDriftEvent` and are audited (CLOUD_DRIFT_DETECTED).

Rate limits, timeouts and partial discovery are first-class results:
discovery records what failed and why, and coverage reflects it
(§15) — see cloud-security-v2.md.
