# Network Drift (Prompt 33 §101–§107)

Network posture is compared against baselines:

- **Baselines are immutable and versioned** (`NetworkBaseline`) — a
  snapshot of host posture (services, versions, TLS, vulnerabilities)
  with a content hash. New baselines increment the version; old ones
  are never edited.
- **Comparison is mechanical**: host added/removed, port opened/closed,
  service added/changed, version changed, TLS changed, new
  vulnerability. Each change is a `NetworkDriftEvent`.
- **Drift is a contextual signal, not a finding.** A new
  remote-management service on a critical production asset raises an
  ELEVATED risk signal; a routine change stays STANDARD. Drift never
  mints a vulnerability by itself.
- **Host absence is ambiguous** (down, filtered, decommissioned) and is
  recorded as such.
- Drift integrates with the Prompt 22 scheduler under the tiered model:
  light checks frequently, safe discovery daily, vulnerability
  reassessment weekly/monthly. EASM drift (Prompt 29) remains the
  external-surface counterpart; this is the internal/network view over
  the same comparison discipline.
