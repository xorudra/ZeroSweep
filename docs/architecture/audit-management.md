# Audit Management (Prompt 26 §64–§75)

An `AuditEngagement` (INTERNAL / EXTERNAL / READINESS / CUSTOMER /
REGULATORY — organizational workflow labels) moves PLANNED →
IN_PROGRESS → EVIDENCE_COLLECTION → REVIEW → COMPLETED → ARCHIVED.

- **Evidence requests** (§67) name a control/requirement, an owner and
  a due date; owners submit workspace evidence, reviewers accept or
  reject. The request owner cannot accept their own submission (§111).
- **Audit findings** (§69) are a separate model from technical
  canonical findings. They may *link* to technical findings by id —
  the records are never merged (§70).
- **Evidence packages** (§71) bundle the assessment snapshot, control
  results, approved evidence only, risk exceptions, and metadata,
  sealed by a hash manifest (see docs/security/audit-package-security.md).
- **Auditor access** (§74/§75) is an explicit grant listing the exact
  assessment/evidence ids shared, with an expiry. Access checks the
  grant on every read; expiry or revocation denies automatically.
  Auditors never get unrestricted tenant access (§143).
