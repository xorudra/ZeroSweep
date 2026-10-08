# Web VAPT Worker Isolation (Prompt 32 §130–§132)

- **Sandboxed execution:** adapters run through the platform
  `ToolRunner` boundary in the worker's container discipline, with
  per-tool CPU/memory/timeout limits from adapter metadata (§130).
- **Argv-only commands (§131):** execution plans are an executable
  name plus an argument array. No plan is ever a shell string; no
  adapter accepts a raw command, shell or args field (the base adapter
  rejects those configuration keys platform-wide).
- **Targets are data (§132/§193):** a target value containing shell
  metacharacters (`;`, `&&`, `$(...)`, backticks) travels as one argv
  element. It cannot become a command, and URL validation rejects
  malformed targets before planning.
- **Secret injection:** credentials reach a running tool only through
  the worker's secret-injection path from the stored reference; they
  are never written into the plan, the job payload, logs or artifacts.
- **Egress discipline:** worker requests inherit the platform SSRF
  posture — scope-locked destinations, metadata ranges blocked, and
  redirect handling that records rather than follows out-of-scope
  destinations (§9/§134/§135).
