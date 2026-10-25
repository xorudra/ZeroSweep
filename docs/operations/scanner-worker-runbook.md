# Scanner Worker Runbook — ZeroSweep

## Pool model

Workers are separated by pool (deploy/policies/scanner-capability-policy.yaml).
A pool runs ONLY the tools/capabilities its policy row allows. If a stage
requests a capability the pool lacks, the stage degrades — the worker
never "borrows" another pool's tooling.

## Routine operations

- **Scale a pool**: `kubectl scale deployment/worker-<pool> --replicas=N`
  (bounded by quota + HPA). Scale on QUEUE signals (waiting jobs, wait
  time), not CPU alone.
- **Tool shows UNAVAILABLE**: the binary is absent from that pool's image.
  This is honest degradation, not an outage. Fix by shipping a pool image
  that carries the pinned tool — never by installing at runtime.
- **Node pressure / disk limits**: ephemeral-storage limits are deliberate.
  Repeated disk-limit terminations → check artifact sizes and the pool's
  `emptyDir` sizeLimit before raising limits.
- **Hung executions**: stale-execution recovery reconciles from the
  database; check WorkerNode heartbeats before restarting anything.

## Safety invariants (never violate, even mid-incident)

- No privileged pods, no hostNetwork, no docker.sock — not "temporarily",
  not for debugging. Debug via logs/metrics/Job TTL artifacts.
- No scan ever runs against an unverified target or unapproved
  assessment; the worker re-checks authorization/scope itself.
- Raw-socket needs go through a ScannerCapabilityPolicy change
  (NETWORK_SAFE, isolated node pool, ELEVATED approval) — never a
  capability add on a general pool.
- Worker restarts are safe: jobs are ID-based and idempotent; a restarted
  worker re-registers and resumes consuming.
