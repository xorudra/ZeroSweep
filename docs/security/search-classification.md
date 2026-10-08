# Search Classification Enforcement (Prompt 27 §27/§28/§128)

Documents carry a classification: PUBLIC < INTERNAL < CONFIDENTIAL <
RESTRICTED. A caller's ceiling is derived from role and the
`VIEW_RESTRICTED_ANALYTICS` permission (OWNER/ADMIN/SECURITY_ENGINEER):

- The ceiling is applied in the Prisma `WHERE`
  (`classification: { in: allowed }`) **before** retrieval — documents
  above the ceiling are never loaded, scored, faceted or suggested.
- Facets and group counts are computed over the already-filtered set, so
  counts cannot leak the existence of restricted material.
- The response states the caller's `classificationCeiling` so clients
  can explain empty results honestly.
- Attack-path access is separately permissioned (`VIEW_ATTACK_PATHS`,
  staff roles) and audited on every read.

Test §128: a VIEWER searching a term that exists only in a RESTRICTED
document gets zero results; a SECURITY_ENGINEER gets the document.
