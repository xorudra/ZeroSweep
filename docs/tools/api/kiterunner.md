# Kiterunner (API route discovery)

**Adapter:** `KiterunnerAdapter` (`packages/security-sdk/src/api/`),
executable `kr`, stage `ROUTE_DISCOVERY`.

Discovers API routes from a governed wordlist and records them as
endpoint inventory with the base URL they were found under.

## Governance

- The wordlist comes from the Prompt 6 `WordlistManager`
  (`API_ROUTES` family): `api-routes-small` for baseline profiles
  (`API_ASSESSMENT`, `WEB_BASELINE`), the standard list for broader
  profiles, comprehensive never auto-selected. Lists are SHA-256
  checksummed; profile selection can only fall downward.
- Discovered routes are **inventory, never findings** — a route name
  alone proves nothing (§51). Checks run later, under their own
  policies.
- Concurrency/rate follow the discovery budget; out-of-scope bases are
  never probed (scope is re-validated in the worker before execution).

## Health

Reports UNAVAILABLE when the `kr` binary is absent from the worker
host — the stage then degrades and the rest of the pipeline continues.
