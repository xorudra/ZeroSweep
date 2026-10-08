# GRC Evidence Security (Prompt 26 §39–§41/§136)

Manual evidence uploads are hostile until validated. The SDK
validator (`validateEvidenceUpload`) enforces, in order:

1. **Size cap** — 10 MiB hard limit.
2. **Archive rejection** — ZIP/7z/RAR/gzip magic bytes are refused;
   evidence is a single file, never an archive to unpack.
3. **Type verification** — the declared content type must match the
   file's magic bytes (PDF, PNG, JPEG, text, JSON only).
4. **Active-content rejection** — HTML/JS/script payloads (including
   `<script`, `<?php`, `javascript:` markers) are refused regardless
   of declared type.
5. **Filename sanitization** — path separators, control characters
   and `..` are stripped before storage; the stored name is never
   used as a path.

Evidence content is stored as data (JSON snapshot / text / reference),
never executed or rendered as active markup.

## Access control

- RESTRICTED evidence content is returned only with
  VIEW_RESTRICTED_EVIDENCE; metadata stays visible so gaps are
  auditable without leaking content (§41).
- Evidence review is permission-gated (REVIEW_EVIDENCE) and
  submitter ≠ approver (SoD).
- Downloads of audit packages are counted and audit-logged; auditor
  downloads go through expiring grants that list the shared ids.
- Every evidence mutation (collect, upload, review, classification
  change, expiry) writes an audit event with actor and before/after
  where applicable (§112).
