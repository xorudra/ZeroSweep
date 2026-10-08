# Product Security (Prompt 40 §261/§167–§175)

- Authorization is the product's core safety property: scans require a
  VERIFIED target, an APPROVED assessment, in-scope assets and policy
  clearance — on every plan, including Enterprise (§16/§168).
- Signup requires an authorization attestation before active testing
  (§70/§168); the attestation is recorded with timestamp + actor.
- Abuse prevention (§169–§172) watches behavioral signals
  (verification churn, scan spikes, protected-target attempts) and can
  warn, throttle, block scan creation or require review. Signals are
  indicators for review — never presented as proof of intent.
- Protected platform targets (§173) — the platform's own domains,
  infrastructure and cloud metadata endpoints (169.254.169.254,
  metadata.google.internal, …) — can never be scanned, on any tier.
- The scan safety ceiling is independent of pricing tier (§174).
- Repository security policy: see `SECURITY.md` (vulnerability
  reporting). Do not file public issues for vulnerabilities.
