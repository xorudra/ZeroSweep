# Kubernetes Hardening (Prompt 38 §53–§57, §72–§85)

- Per-service service accounts (§72), `automountServiceAccountToken:
  false`, RBAC with no wildcard verbs (§73 — the chart's API SA can
  read its own ConfigMap only in reference policies).
- Pod security: non-root, read-only root fs, dropped capabilities,
  seccomp (§74); resource requests/limits on every container (§75).
- NetworkPolicies ship default-deny + explicit allows in both the
  Kustomize base and the Helm chart (§53–§57); PostgreSQL/Redis are
  never Internet-reachable.
- HPAs scale stateless tiers on CPU/memory; scanner pools scale on
  queue depth, never HTTP rate; PDBs protect api/web during voluntary
  disruptions (§83).
- Admission policy examples live in `deploy/policies/` (Prompt 25):
  privileged workloads and `:latest` images are rejected.
