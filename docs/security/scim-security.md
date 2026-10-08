# SCIM Security (Prompt 23)

- Dedicated SCIM bearer tokens — never user credentials or API keys —
  scoped to exactly one organization by construction (§67, §141).
- Tokens are stored as SHA-256 hashes with a lookup prefix; rotation
  immediately invalidates the previous token; use updates `lastUsedAt`.
- Role assignment privilege boundary: provisioning payloads CANNOT set
  roles. Roles come only from administrator-approved group mappings;
  fixtures prove an unmapped "Domain Admins" group yields VIEWER (§131).
- Filters pass through a strict allowlist parser — boolean injection and
  SQL tokens are rejected; evaluation is in-memory (§130).
- Deprovisioning is disable-and-revoke (access + sessions), preserving
  the records auditors need (§69, §132).
