# DevSecOps Data Redaction (Prompt 24 §117–§119, §42)

External systems receive the minimum useful view of a finding:

- **Sanitization**: finding/commit/PR text is stripped of ANSI
  escapes, control characters and bidi overrides, and length-capped
  before it can enter a ticket, check summary, chat message or event.
- **Secret scrubbing**: credential-shaped content (cloud keys,
  provider tokens, private keys, JWTs, credential assignments) is
  replaced with `[REDACTED]` in every outbound artifact — tickets,
  PR decoration, SARIF, SIEM events, webhook payloads (§119).
- **Pipeline summaries (§42)**: secret findings expose only the
  finding id, repository-relative file, line, severity and guidance.
  The detected value is never in the payload — it is not stored
  anywhere it could be copied from.
- **Delivery records (§80)**: response bodies are never stored with
  delivery attempts; only status/category/duration metadata.
- **Evidence**: reports and exports reuse the platform redaction
  service from earlier phases; integration code has no path to raw
  evidence secrets.
