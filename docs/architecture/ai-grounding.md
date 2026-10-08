# AI grounding, citations & confidence (Prompt 21 §21–§27)

## Grounding (§21)

`AIGroundingService` admits a citation only when its `sourceId` was
actually present in the context the model received. Citations pointing
anywhere else — invented or cross-tenant — are dropped. Identifiers
(CVE ids, record ids) that appear in an answer but not in the context
are reported as **unsupported references**; the response is marked
`INSUFFICIENT_EVIDENCE` (§25) rather than silently shipped.

## Citations (§22/§23)

Every grounded response carries `AiCitation` rows: claim, sourceType
(FINDING / OBSERVATION / EVIDENCE / ASSET / CVE / CWE / KEV / EPSS /
SBOM_COMPONENT / GRAPH_RELATIONSHIP / COMPLIANCE_CONTROL /
DOCUMENTATION), sourceId, optional evidence reference and confidence.
Citations persist with the request log, so any answer can be audited
back to the exact platform records behind it.

## Confidence (§26/§27)

`AIConfidenceService` combines citation coverage, source quality
(TRUSTED share of context), scanner confidence, verification state,
injection-scan trust and missing-field penalties into LOW / MEDIUM /
HIGH. Confidence is a heuristic signal for the analyst — it is never
presented as certainty, and the deterministic engines (Risk Engine
V3, RetestRouter) remain authoritative wherever they own a decision
(§31/§37/§53).

## Hallucination discipline (§89–§91)

Asked about an identifier absent from context, the copilot answers
INSUFFICIENT_EVIDENCE. The deterministic MOCK provider implements the
same contract, so the behavior is testable offline and identical in
shape to a real provider's obligations. Report drafting is grounded
in the **immutable ReportSnapshot** (§49/§102): mutating a live
finding after issuance cannot change what the draft was based on.
