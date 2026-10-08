# Kubernetes Assessment Operations (Prompt 34)

## Flow

1. Register the cluster (Kubernetes page) — apiServerReference +
   credential reference only; kubeconfig content is never accepted.
2. Import RBAC inventory (POST /kubernetes/clusters/:id/rbac) from
   your collection export when the live transport is not wired.
   Token/secret-shaped fields are refused by design.
3. Run the V2 assessment (Kubernetes Security page): pipeline covers
   RBAC, workload configuration, benchmarks, image correlation,
   exposure, runtime signals.
4. Review order: cluster-admin bindings → wildcard roles →
   privileged/hostNetwork public workloads → attack-path candidates
   → benchmark deviations → baseline drift.

## Interpreting results

- COMPLETED_WITH_GAPS with a CONNECT gap means the run used
  recorded inventory — freshness is bounded by the last collection.
- Benchmark output is CIS evidence, never certification (§79).
- Attack paths are candidates for review, not proof of exploitability.
- Falco correlation confidence HIGH means "this workload's image has
  a known CVE and the event touched it" — not "the CVE was
  exploited". Keep the distinction in incident notes (§95).
