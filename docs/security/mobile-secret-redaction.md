# Mobile Secret Redaction (Prompt 35 §30–§32/§91/§154)

- **Detection** (§30) reuses the platform SecretDetection
  architecture over artifact content: API keys, tokens, private-key
  material, credentials, cloud credential patterns.
- **Storage** (§31): fingerprint + type + location + redacted
  preview — never the raw secret, whenever possible. There is no
  column in the mobile/binary schema that could hold a raw secret
  value.
- **No validation** (§32): discovered secrets are NEVER tested
  against external services automatically.
- **Traffic** (§91): Authorization, Cookie, tokens, passwords, API
  keys and personal-data fields are redacted before persistence,
  logs, reports or AI context. The §154 test plants a synthetic
  Bearer token in fixture traffic and proves it appears in none of
  those surfaces; `POST /api/v1/mobile/traffic-redaction-preview`
  runs the same redactor without persisting anything.
- **Decompiled evidence** (§28/§29): bounded snippets are sanitized
  value-by-value at intake (Prompt 17), so a secret inside a snippet
  is stored nowhere.
