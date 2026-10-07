# Binary Sandbox (Prompt 18 §8–§11)

Artifacts are hostile content. The static sandbox treats them as
**data, never code**:

- Parsers operate on Buffers in-process with fail-safe bounds — no
  `dlopen`, no mapping as code, no execution path exists in the SDK,
  worker or API. The §100 no-execution test proves an embedded marker
  payload never fires during a full `BINARY_COMPREHENSIVE_STATIC`-class
  analysis.
- Executing adapters (checksec, radare2, Ghidra headless) run in
  containers with `NO_NETWORK`, the artifact mounted read-only by
  reference, ephemeral workspaces, and hard timeouts. Ghidra runs ONE
  administrator-approved script from the governed scripts directory;
  script selection is never configuration.
- Firmware/archive intake follows the hostile-archive discipline
  (§7 + P12): zip-slip paths, symlinks escaping the boundary, and
  size/ratio bombs are rejected by the intake validator, and hostile
  fixtures prove the rejection in tests.
- Worker capabilities are separated by environment: static analysis
  (`BINARY_STATIC_ANALYSIS`) and the dynamic lab (`BINARY_DYNAMIC_LAB`)
  are different worker types; neither deployment env can grant the
  other (§10).
- Budgets bound hostile inputs: artifact size, function/string/symbol
  counts, analysis + decompile time, project size, debug duration,
  crash artifact count and memory-capture bytes (`ScanBudget` binary
  extensions, §82).
