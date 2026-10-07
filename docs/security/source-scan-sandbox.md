# Source Scan Sandbox & No-Code-Execution Policy (Prompt 12 §13–§15)

Repository content is untrusted. The source pipeline is built so that
analyzing a hostile repository is safe by construction:

## Never execute the target (§15/§30)

- `RepositoryExecutionPolicy` defaults to `DO_NOT_EXECUTE_SOURCE` and
  the worker derives every tool configuration itself — snapshot path,
  repository identity, languages — never from client input.
- Forbidden, always: build scripts and compilers over target code,
  package-manager lifecycle hooks (`preinstall`/`postinstall`/…), git
  hooks (clone plans pin `core.hooksPath=/dev/null` and an empty
  credential helper, `GIT_TERMINAL_PROMPT=0`), target test suites,
  repository-supplied Semgrep rules or CodeQL queries.
- Tool adapters run with a **NO_NETWORK** plan policy on the
  `SOURCE_ANALYSIS` worker capability; workers hold no Docker socket.
- Tools that would need a build (CodeQL on compiled languages without
  a no-build mode, SpotBugs without bytecode) report `BUILD_REQUIRED`
  or skip — they never trigger one.

## Intake hardening (§7–§12)

- Git URLs: https/ssh/git only; embedded credentials rejected;
  metadata (169.254.169.254), loopback and private ranges blocked
  unless an approved internal engagement allows internal destinations;
  clone depth/size/timeout bounded by the source scan budget (§83).
- Archives: central-directory inspection before any extraction;
  zip-slip traversal, symlink/hardlink escapes, nested archives,
  decompression ratio > 100 and file-count/size caps all reject the
  archive. Hostile-archive fixtures prove each rejection.
- Snapshot manifests: every path must normalize to a safe
  repository-relative path at registration time.

## Data handling

- Analysis output is parsed by bounded, hostile-input-safe parsers
  (SARIF caps 25 MB / 10,000 results; XML readers reject DOCTYPE and
  entities; snippets are ANSI-stripped, secret-redacted and capped).
- Secrets are fingerprinted at parse time and never persisted
  (see `docs/architecture/secret-scanning.md`).
- Exclusions (paths, rules, fingerprints, dependencies) are explicit,
  reasoned, admin-governed and audited (§85/§86) — never silent.
