# GRC Segregation of Duties (Prompt 26 §111)

| Workflow | Rule | Enforcement |
| --- | --- | --- |
| Evidence review | Submitter cannot approve own evidence | EvidenceService.reviewEvidence rejects submitter == reviewer when approval is required |
| Audit evidence requests | Request owner cannot accept own submission | GrcAuditService.reviewRequest |
| Risk acceptance | Requester cannot approve own HIGH/CRITICAL acceptance | SDK evaluateAcceptanceSoD + RiskService.decideAcceptance |
| Requirement review | Requirement owner cannot approve own requirement | AssessmentService.reviewRequirement |
| Assessment completion | Creator cannot be sole approver | Reviewer chain above; COMPLETED requires all requirement reviews APPROVED |
| Auditor access | Grants list exact shared ids; no tenant-wide auditor role | AuditorAccessGrant + auditorCanAccess on every read |

All SoD denials are returned as 403 and the mutation does not occur.
Permissions themselves are capability-based (§110) — role names
alone never grant a GRC action.
