# Repository Ingestion Security (Prompt 24 §85–§89)

- **Allowlist (§86)**: only repositories present in
  `RepositoryIntegrationLink` can be synced or trigger work. Provider
  API access is broader than the platform's trust — the link table
  narrows it.
- **Metadata-only sync**: synchronization imports provider metadata.
  Code arrives only through the Prompt 12 governed snapshot path
  (content-hashed, immutable, hostile-content checked: zip-slip,
  symlink-escape and archive-bomb rejection) — never through a
  webhook-pushed clone.
- **Submodule policy (§87)**: submodule URLs must parse as URLs, must
  be HTTPS, and must pass the SSRF destination policy
  (`blockedTargetReason`) — internal/loopback/link-local submodule
  targets are refused at plan time.
- **Budgets (§89)**: clone/fetch planning enforces file-count and
  size budgets plus a 100x expansion-ratio bomb check before any
  byte is fetched. Path math for extracted entries refuses escapes
  outside the ingestion root.
