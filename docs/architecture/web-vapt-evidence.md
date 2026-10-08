# Web VAPT Evidence (Prompt 32 §113–§117)

Evidence for V2 findings follows the platform evidence discipline:

- **Sanitized before persistence:** request/response copies pass the
  platform redactor (authorization headers, cookies, bearer/basic
  credentials, secret-shaped fields) before they are stored in
  `WebVaptEvidence` (§114).
- **Size-capped:** bodies are truncated to the evidence cap; large
  material lives in object storage behind `artifactRef` — never as a
  Postgres blob (§115). Each record carries its byte size and SHA-256.
- **Markers, not payloads:** XSS/injection proofs store the harmless
  marker classification (§71/§76); reflected attack strings from a
  target are truncated and redacted evidence of the check, never a
  stored working payload.
- **Screenshots (§116):** restricted to profiles that explicitly
  enable them; they follow the same sanitization + artifact rules.
- **Access (§166):** evidence reads require `VIEW_VAPT_EVIDENCE`.

Fixture discipline: the planted fixture credential used in tests must
never appear in any parsed finding, evidence string, log or report —
the SDK test suite asserts its absence from SQLmap fixture parsing
(§178).
