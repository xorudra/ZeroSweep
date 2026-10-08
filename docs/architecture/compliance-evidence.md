# Compliance Evidence (Prompt 26 §19–§27)

`ComplianceEvidence` is a **snapshot**: at collection time the
collector reads an authorized platform source (asset inventory,
findings of every class, SAST/SCA/SBOM, secrets, identity posture,
MFA/SSO configuration, DevSecOps gates, backup verification, DR
tests, audit events, continuous snapshots, access reviews — §19),
stores the normalized content, and seals it with a SHA-256 hash over
the canonical JSON. Later changes to the source cannot alter the
stored evidence (§21), which is what makes evidence usable for an
issued assessment or audit package.

## Classification & access

PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED (§23). Restricted
evidence content is returned only to roles holding
VIEW_RESTRICTED_EVIDENCE; other members see metadata with the
snapshot withheld (§41).

## Freshness

`EvidenceFreshnessPolicy` is **per control** (§25): MFA configuration
evidence goes stale in 30 days, vulnerability-scan evidence in 14,
backup-restore evidence in 3, DR-test evidence in ~a year. Freshness
is *derived* at read time (`CURRENT → STALE → EXPIRED`); stored
INVALID / SUPERSEDED states are sticky. Expired evidence emits an
EVIDENCE_EXPIRED audit event and a drift event when observed.

## Manual evidence

Uploads (PDF, documents, screenshots, structured records — §39) pass
the hostile-file defenses (see docs/security/grc-evidence-security.md)
and land as PENDING review. A reviewer approves / rejects / requests
changes (§38); the uploader can never approve their own evidence
where review is required (SoD, §111). Only NOT_REQUIRED or APPROVED
evidence supports an assessment result or an audit package.
