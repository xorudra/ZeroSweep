# AI data redaction (Prompt 36 §18–§20, §125–§127)

Redaction happens BEFORE provider routing decisions are finalized
and before any provider call — in the context builder, not at the
provider edge.

## Rules

- SECRET-classified fields (passwords, tokens, private keys,
  authorization headers, session material) are REMOVED from
  context, not masked — a masked secret still leaks length/shape.
- Redaction is pattern + field-name based and runs over every
  context section, including free text in findings and tickets.
- Redaction counts are logged (§129 metadata); the redacted values
  themselves are never logged anywhere.
- Provider policies (§125): external providers additionally respect
  workspace data policies (residency, classification ceiling,
  source-code allowance); SECRET data never routes externally (§6).
- Retention (§127): traces retain METADATA only (90 days default);
  full prompts/responses are not stored in traces at all. Knowledge
  documents keep their own classification and ACLs (§24).
