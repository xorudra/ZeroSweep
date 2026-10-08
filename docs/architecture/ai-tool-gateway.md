# AI security tool gateway (Prompt 36 §27–§35)

The gateway is the only path from AI components to platform data and
actions. There is no generic HTTP tool, no arbitrary URL fetch, no
shell, no SQL, no cloud/Kubernetes/device API (§26/§115).

## Catalog

- **READ**: getAsset, searchAssets, getFinding, searchFindings,
  getScan, getCoverage, getSBOM, getCveIntel, getRiskExplanation,
  getRemediationStatus, getIncident.
- **ANALYZE**: compareScans, compareVersions, correlateFindings,
  calculateExistingRisk, buildAttackPathView, summarizeCoverage.
- **PLAN**: draftScanPlan, draftVerificationPlan,
  draftRemediationPlan, draftInvestigationPlan.
- **SAFE_ACTION** (create drafts/proposals in owning workflows):
  createScanDraft, createRemediationTicket, requestVerification,
  generateReportDraft, createInvestigationCase.
- **RESTRICTED_ACTION**: scheduleApprovedScan — requires an APPROVED
  plan, an authorization snapshot AND a recorded human approval.

## Gate (§28/§29/§35)

Every call is evaluated deterministically: catalog membership →
permission → argument schema (extra fields REJECTED) → workspace
scoping → authorization requirement → approval requirement → rate
limit. Verdict codes: UNKNOWN_TOOL, PERMISSION, ARGUMENT_SCHEMA,
AUTHORIZATION_REQUIRED, APPROVAL_REQUIRED, RATE_LIMIT.

Tool arguments are never written to logs or traces (§132) — only
tool name, verdict and argument KEY names.
