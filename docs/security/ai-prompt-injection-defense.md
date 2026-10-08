# Prompt-injection defense (Prompt 36 §59–§63)

Retrieved content — findings, tickets, documents, web content, CVE
text, SBOM notes — is UNTRUSTED data. It is wrapped in labelled
context sections and can never become instructions.

## Defenses (layered)

- **Detection** (Prompt 21): eight detector families scan inputs and
  retrieved text, including base64-decoded payloads; hits are
  labelled in context and counted in observability.
- **Structure**: system policy states records are data; tool names
  and step capabilities come only from the closed catalogs, never
  from model output parsing.
- **No instruction channel**: model output cannot create tools,
  plans with new capabilities, approvals or scope — the planner
  validator and gateway gate are deterministic code paths the model
  cannot influence.
- **Red-team coverage**: §115's malicious-document case runs in the
  evaluation suite; the document's embedded instruction is detected
  and the answer stays a summary (see ai-evaluation.md).
- **Output side**: responses are sanitized (no raw HTML/script),
  structured outputs schema-validated, CVE mentions verified
  against context + the intel dataset (§68).
