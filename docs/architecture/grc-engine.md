# GRC Engine (Prompt 26)

The Governance, Risk & Compliance engine layers over the existing
platform — organizations/workspaces, enterprise identity, the unified
vulnerability manager, Risk Engine V3, the scheduler, the reporting
engine and the append-only audit log. It creates **no** duplicate
vulnerability-management or audit-log system.

**ZeroSweep does not certify.** It provides technical evidence, control
monitoring, assessment support, risk tracking and audit preparation.
Certification/attestation remains the responsibility of qualified
auditors/assessors and the organization. Every dashboard and report
carries this disclaimer, and the headline metric is labelled
"Assessment Coverage / Control Status" — never a certification score.

## Module map (apps/api/src/modules/grc)

| Area | Service | Responsibility |
| --- | --- | --- |
| frameworks | FrameworkService | Versioned framework registry + import |
| controls | ControlService | Control library, owners, tests, mappings, catalog seeding |
| evidence | EvidenceService | Snapshot evidence collection, manual upload, review, freshness |
| monitoring | MonitoringService | Signal derivation, control evaluation, drift, schedules |
| assessments | AssessmentService | Assessments pinned to framework versions, snapshot results, review |
| risks | RiskService | Register, inherent/residual risk, treatments, acceptances (SoD + expiry), reviews |
| policies | PolicyService | Governance policy lifecycle, acknowledgements, retention config |
| audits | GrcAuditService | Engagements, evidence requests, audit findings, packages, auditor grants |
| vendors | VendorService | Vendor risk foundation |
| findings | FindingLinkService | Finding ↔ control suggestions + analyst overrides |
| analytics | GrcAnalyticsService | Compliance / framework / risk / evidence dashboards |
| reports | GrcReportService, GrcBackupService | Immutable report snapshots, exports, GRC backup/restore |
| ai | AiGrcService | Grounded AI GRC assistant + deterministic NL query plans |

Pure mathematics and data live in `@dsrclone/security-sdk` (`src/grc`):
the versioned framework catalog, the control library, cross-framework
mappings, risk-matrix computation, evaluation/freshness functions,
evidence hashing, hostile-upload validation, audit-package manifests
and the AI safety composer. Services never re-implement them.

## Data flow

```
platform state (identity policy, posture snapshots, findings,
posture assessments, access reviews, gates, SBOMs)
  → signal derivation (MonitoringService.deriveSignals)
  → control evaluation (SDK evaluateControl) → ControlEvaluation
  → evidence collection (snapshot + SHA-256) → ComplianceEvidence
  → assessment computation (SDK requirementResult) → AssessmentRequirementResult
  → audit package (redacted bundle + hash manifest) → AuditEvidencePackage
```

## Safety invariants

- A control/requirement without evidence is INCONCLUSIVE /
  NOT_ASSESSED — never a pass.
- Evidence collection never starts a scan; if new technical evidence
  is required it goes through the existing scheduler/scan pipeline.
- Control-test schedules trigger read-only re-evaluation only.
- Expired risk acceptances return risks to review automatically.
- Historical assessments and issued reports/packages are immutable
  snapshots; later source changes never rewrite them.
