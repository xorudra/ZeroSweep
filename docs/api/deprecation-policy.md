# API & Feature Deprecation Policy (Prompt 40 §197)

- Plans: DRAFT → ACTIVE → DEPRECATED → RETIRED (§7). DEPRECATED plans
  keep working for existing subscriptions; RETIRED plans accept no
  new subscriptions. Existing subscriptions always keep their
  historical plan VERSION (§8).
- APIs: a deprecated route is announced in release notes, kept for at
  least one minor release train, and removed only in a major version.
- Release channels (§186): STABLE / RC / BETA / NIGHTLY. Update
  metadata is signed; updates are never auto-executed (§188).
