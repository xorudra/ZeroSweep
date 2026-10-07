# Directory Drift (Prompt 15 §79–§80)

Every collection records a content-hashed `DirectorySnapshot`
(object counts, relationship count, collector versions, SHA-256 over
the canonical normalized inventory). On each subsequent collection
the platform diffs the pre-collection persisted state against the new
state and records `AdDriftEvent` rows.

## Event kinds

`NEW_PRIVILEGED_MEMBER`, `NEW_PRIVILEGED_USER`,
`PRIVILEGED_MEMBERSHIP_REMOVED`, `NEW_TRUST`, `TRUST_CHANGED`,
`GPO_CHANGED`, `DELEGATION_CHANGED`, `NEW_RISKY_ACL`,
`CERTIFICATE_TEMPLATE_CHANGED`.

## Framing

A drift event is a **review signal for an analyst** — it is never
classified malicious automatically (§80). New privileged membership
may be a legitimate joiner; a new trust may be an approved project.
The event carries the object reference and a plain-language detail so
the review starts from evidence, and the detection is audited
(`AD_DRIFT_DETECTED`) with counts only — never with directory
payloads.
