# Network Tool Safety (Prompt 33 §27–§38, §136/§137)

- Tools execute in isolated scanner workers via ARGUMENT ARRAYS built
  from validated values (targets from normalization, ports from the
  port policy, options from allowlists). Shell strings are never
  constructed from user input; there is no shell downstream.
- **Masscan** requires all of: an explicit high-throughput request, the
  RUN_HIGH_THROUGHPUT_PORT_SCAN permission, a recorded platform
  permission, strict scope, and the Prompt 10 hard limits (rate,
  targets, ports, duration). Any failure = MASSCAN_NOT_APPROVED,
  recorded on the plan. Excessive rate requests are refused, not
  silently honored.
- **NSE categories (V2)**: SAFE / DISCOVERY / VERSION run under the
  Prompt 10 catalog discipline; VULN_APPROVED is a small curated
  check-only set requiring the NETWORK_VULNERABILITY profile + a
  recorded workspace allowlist + RUN_NETWORK_VULNERABILITY_SCAN;
  BRUTE / DOS / EXPLOIT / INTRUSIVE_UNAPPROVED are structurally
  blocked for every profile, role and approval. The exact scripts used
  are recorded on the plan.
- **No authentication attacks**: no Hydra/Medusa/spraying/stuffing or
  brute force exists anywhere in the network stack. "Anonymous access"
  checks consume recorded protocol evidence under profile gates; the
  platform never performs a login.
- Timeouts, CPU/memory limits and network restrictions are enforced by
  the worker envelope (Prompt 4/10), unchanged.
