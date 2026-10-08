# Kubernetes Credential Security (Prompt 34 §71/§72/§83/§84/§156)

- The kubeconfig NEVER enters the platform: clusters register with
  an `apiServerReference` name; the actual kubeconfig lives in
  Secrets Management / the worker's secret mount and is referenced,
  never uploaded, stored, echoed or logged. There is no API field
  that accepts kubeconfig content; hostile manifests are parsed with
  the hardened YAML parser (no code execution at parse time).
- The platform's cluster identity is least-privilege and read-only
  (get/list/watch on posture resources). Cluster-admin credentials
  are refused by policy — and if inventory shows the platform
  identity bound to cluster-admin, RBAC analysis flags it CRITICAL.
- Secret VALUES are never inventoried: inventory carries secret
  NAMES and consuming workloads only (§83). RBAC import refuses
  token/secret-shaped fields outright (test-asserted).
- Service-account tokens are never harvested, requested or stored
  (§84). Token review/request endpoints do not exist.
- When a kubeconfig/transport is absent, coverage reports the gap
  (SECRET_UNAVAILABLE / TOOL_UNAVAILABLE) — never a fabricated
  connection (§156).
