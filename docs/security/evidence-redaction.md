# Validation Evidence Redaction (Prompt 16 §33–§35)

Validation evidence is evidence **about a security check**, and checks
touch live systems — so evidence can contain secrets even when nobody
asked for them (a target that echoes an `Authorization` header back, a
cookie in a recorded response, a token inside an error page).

## Rule: sanitize before storage, always

Nothing reaches the database unsanitized. The pipeline
(`packages/security-sdk/src/validation/evidence.ts`) runs at capture
time in the worker and again for analyst-supplied manual evidence in
the API:

1. **Structured redaction** (shared with Prompt 7 evidence handling):
   `Authorization` headers, cookies, tokens, API keys, passwords,
   private keys, session IDs and cloud credentials are replaced with
   `[REDACTED …]` markers.
2. **PEM blocks** are removed wholesale.
3. **Cloud key shapes** (e.g. AWS access key IDs) are redacted wherever
   they appear.
4. **Free-text assignments** (`token=…`, `password: …`, `api_key - …`)
   inside prose/log excerpts are redacted.
5. **Secret-shaped object keys** (`password`, `token`, `secret`,
   `apiKey`, …) have their values replaced wholesale — the shape of
   the value is never trusted.
6. Circular structures and oversized artifacts are truncated to
   summaries (64 KB cap).

## Integrity (§35)

Each stored artifact carries: a **SHA-256 checksum of the sanitized
artifact**, timestamp, source tool, and links to its session and
finding. Because the checksum is computed *after* redaction, anyone can
verify the stored evidence is byte-identical to what ZeroSweep recorded
without the checksum ever covering a secret.

## Access

Reading evidence requires `VIEW_VALIDATION_EVIDENCE` and is audited
(`VALIDATION_EVIDENCE_ACCESSED`, §80). Audit records themselves never
contain secrets (§81) — they carry actor, target, finding, validator,
risk class, policy decision and approval identifiers only.

## Reports

Proof-of-validation summaries (§61) are generated from session
metadata and evidence **checksums** — never from raw evidence content —
so reports cannot leak the sensitive data evidence redaction removed.
