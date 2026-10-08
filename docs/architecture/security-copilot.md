# Security copilot (Prompt 21 + Prompt 36)

The copilot is an analyst assistant over normalized platform data.
V1 (Prompt 21) established the pipeline — RBAC → context → injection
scan → redaction → policy → budget → provider → grounding →
confidence → sanitize → log/audit — and V2 (Prompt 36) adds routing,
retrieval governance, the tool gateway, planning and agents around
it without changing the pipeline's safety order.

## Task types

V1: FINDING_EXPLANATION, REMEDIATION_GUIDANCE, SECURE_CODE_GUIDANCE,
EXECUTIVE_SUMMARY, SCAN_SUMMARY, ASSET_SUMMARY, KNOWLEDGE_QA,
COPILOT_CHAT, ATTACK_SURFACE_SUMMARY, TREND_SUMMARY.
V2 (§4): SECURITY_QA, ASSET_ANALYSIS, VULNERABILITY_ANALYSIS,
ATTACK_PATH_ANALYSIS, SCAN_PLAN_DRAFT, SOC_INVESTIGATION,
INCIDENT_SUMMARY, GRC_EVIDENCE_SUMMARY, EXECUTIVE_SUMMARY,
TREND_ANALYSIS, VERSION_COMPARISON.

## Grounding rules

- Answers cite only records present in context (§22/§67).
- A CVE absent from context and the local intel dataset is refused
  with INSUFFICIENT_EVIDENCE — the model must not invent one (§68).
- Risk scores come from the stored Risk Engine V3 explanation (§70).
- Natural-language queries compile through a deterministic parser
  into typed view-models — never AI-generated SQL.
- Provider failure ⇒ labelled RULE_BASED fallback over the same
  governed records, never presented as an AI answer.
