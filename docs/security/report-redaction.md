# Report Redaction (Prompt 37 §40/§90/§91)

Redaction is layered so no single miss can leak a secret into a
report or the portal:

1. **Build time.** `buildReportSnapshot` runs `redactReportText` over
   finding descriptions, evidence summaries and remediation text.
   It masks the platform evidence patterns plus PEM private keys,
   cookies, and assignment-shaped secrets (`password: x`,
   `api-key: x`, `token: x`). Redaction happens once, so every
   rendering (PDF/HTML/JSON/CSV) inherits it.
2. **Portal projection.** `redactClientText` (SDK `reporting2`)
   additionally masks emails and AWS access keys for client-facing
   fields.
3. **Finalization gate.** Before a report can be finalized, the
   redaction preview scans the frozen snapshot for secret-shaped
   content (private keys, bearer tokens, cookies, password/API-key/
   token assignments, AWS keys). Unresolved warnings block
   finalization (§91). Identifier subtrees (ids, hashes,
   fingerprints) and the platform's own `[REDACTED]` markers are
   excluded so integrity fields never false-positive.
4. **Exports.** Vulnerability exports run the same client redaction
   over free-text fields, and CSV cells pass the formula-injection
   guard (§124/§149).

The §142 test plants password/token/cookie/private-key material and
asserts absence from the snapshot, every render format, the portal
projection and exports.
