# Reporting V2 (Prompt 37 §61–§94)

Reporting V2 is a workflow and delivery layer over Prompt 20's
reporting substrate — `SecurityReport`, the immutable
`ReportSnapshot`, and the deterministic SDK renderers. There is no
second report engine.

- **Workflow** (§62): DRAFT → IN_REVIEW → (CHANGES_REQUESTED → IN_REVIEW)
  → APPROVED → FINALIZED → ARCHIVED, projected from the stored
  approval fields by `v2ReportState`. Separation of duties (§85) is
  enforced when a report's `requireSeparateApprover` policy is set.
- **Finalization** (§83/§93): copies the frozen snapshot document
  into an immutable `ReportVersion`, renders the artifact, and stores
  its SHA-256 (`artifactHash`). Signature support is metadata only —
  signer identity, timestamp, certificate reference — with no claim
  of legal validity (§94).
- **Redaction gate** (§90/§91): finalization runs the SDK redaction
  preview over the snapshot; unresolved secret-shaped content blocks
  finalization. Platform-built snapshots pass because
  `redactReportText` masks assignment-shaped secrets at build time.
- **Templates** (§66/§67/§80/§81): every edit is a new version;
  published versions never change. Branding values are validated:
  logo references are object-storage reference names (embedded or
  remote payloads refused), colors are `#RRGGBB`, confidentiality
  text is static.
- **AI drafts** (§86–§89): generated only from the frozen snapshot
  and fact-checked before storage; unsupported claims block the
  draft. The built-in drafter is deterministic and labelled
  RULE_BASED. AI output can be a draft, never an approval.
- **Formats** (§76–§79): PDF/HTML/JSON/CSV render deterministically
  from the frozen document. DOCX is not offered (no reliable writer
  in the stack; §79 makes it optional).
- **Share links** (§106): see `report-access-control.md`.
