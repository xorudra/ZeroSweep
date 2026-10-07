# Steampipe Adapter (Prompt 14 §32/§33)

## Purpose
SQL-as-inventory over cloud APIs, restricted to **governed query
packs**: versioned, platform-approved check packs (CIS foundations per
provider, public-exposure inventory).

## Capabilities
`CLOUD_QUERY`, `CSPM`

## Supported target types
AWS, AZURE, GCP (registered cloud accounts)

## Risk level
PASSIVE — read-only queries from approved packs only.

## Execution mode
CONTAINER: `steampipe check <pack-id> --output json`.

## Governance (§32)

- The adapter accepts a `queryPack` id from the approved pack list
  (`aws-cis-foundations`, `azure-cis-foundations`,
  `gcp-cis-foundations`, `aws-public-exposure`) — selected by the
  account/scan configuration, resolved by the worker.
- **Arbitrary SQL is refused at plan time.** A `sql` field exists in
  the input schema solely so a supplied query can be explicitly
  rejected (`ARBITRARY_SQL_FORBIDDEN`); unknown pack ids are rejected
  (`UNKNOWN_QUERY_PACK`). There is no code path that executes
  user-authored SQL against a cloud account.
- Connection configuration is a credential/endpoint surface: endpoints
  pass the SSRF guard (§101) and connection strings are never stored.

## Output handling
Rows with status `alarm`/`fail` become findings on canonical rules;
`ok` rows are PASS evidence for control assessments (§23 discipline).
