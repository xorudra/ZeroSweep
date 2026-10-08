# Search Data Redaction (Prompt 27 §25/§111/§112/§130)

- Index documents are built through `redactForAi`: SECRET-classified
  fields are **removed**, not masked, before text reaches
  `SecuritySearchDocument.searchableText`.
- Snippets are produced from already-redacted text and then HTML-escaped
  (`makeSnippet`), so a snippet can neither leak a secret nor inject
  markup (§129).
- Dead-letter entries store a sanitized summary (event type, resource
  type/id, validation codes) — never raw event bodies, which might carry
  secrets.
- Exports pass the same redaction path and are row-limited and audited
  (`ANALYTICS_EXPORTED`, §102).
- AI analytics answers cite documents; the underlying text was redacted
  at index time, so citations cannot surface secrets (§104–§109).

Test §130 plants an AWS-shaped key in a finding description and asserts
its absence from the built index document.
