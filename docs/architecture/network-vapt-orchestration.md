# Network VAPT Orchestration (Prompt 33 §10–§18)

A scan plan is built before anything runs and is the unit of
governance:

1. **Profile** — one of NETWORK_DISCOVERY, NETWORK_SAFE,
   NETWORK_STANDARD, NETWORK_VULNERABILITY, TLS_NETWORK,
   TARGETED_SERVICE_VERIFICATION. Production defaults are conservative:
   no vulnerability scanners outside NETWORK_VULNERABILITY, no
   full-TCP port range anywhere by default, UDP off unless a profile
   enables a small bounded set, Masscan in no default tool list.
2. **Budget** — hosts/ports/rate/concurrency/duration (+ separate UDP
   budget), clamped one-directionally against the platform ceiling.
   Workspace admins cannot raise the ceiling; clamped fields are
   returned and shown.
3. **Scope snapshot** — frozen at plan/run start (hosts, CIDRs,
   exclusions, SHA-256 hash) into the canonical `ScanScopeSnapshot`.
   A running scan cannot expand beyond it; discovered hosts outside it
   become candidates, never targets.
4. **Stage jobs** — the §13 pipeline stages are queued, cancellable,
   timeout- and resource-bounded (budgets), and observable via plan +
   coverage records.
5. **Tiered monitoring** (§105–§107): light service checks frequently,
   safe discovery daily, vulnerability reassessment weekly/monthly —
   continuous full vulnerability scanning is never the default.
