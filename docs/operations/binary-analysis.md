# Binary Analysis Operations (Prompt 35 §51–§70)

- Register artifacts by SHA-256 (`POST /binaries`); analyze via
  `POST /binary/artifacts/:id/analyze` with `BINARY_STATIC` or
  `BINARY_HARDENING`. Execution rides the Prompt 18 gated scan path
  on BINARY targets.
- Coverage (`GET /binary/artifacts/:id/coverage`) is the operator's
  honesty check: FORMAT_PARSING, HARDENING, IMPORTS_EXPORTS,
  STRINGS, FUNCTIONS, DEPENDENCY_ANALYSIS, DECOMPILATION (§123).
  A NOT_CONFIGURED decompiler shows as a DECOMPILATION gap — the
  pipeline continues (§64/§149).
- Diffs (Prompt 18 `BinaryDiff`) compare two artifacts' inventories;
  debug sessions are governed LAB records with separation of
  duties and no transport in this environment (NOT_PROVISIONED).
- Load discipline (§161): ingestion, hashing, queues, normalization,
  SBOM correlation, version comparison and dashboard queries are
  all bounded (string/component/finding caps). No benchmark numbers
  are published without a measured run.
