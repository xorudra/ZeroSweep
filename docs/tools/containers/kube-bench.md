# kube-bench

**Adapter:** `KubeBenchAdapter`, executable `kube-bench`, capabilities
`KUBERNETES_CIS_ASSESSMENT`, `COMPLIANCE_ASSESSMENT`. Classification:
**INTERNAL_PRIVILEGED** (§39). Worker: `PRIVILEGED_HOST` only.

CIS Kubernetes Benchmark checks for an explicitly approved cluster.
Executor-gated exactly like Docker Bench: no privileged worker
capability, no run — the posture stage degrades honestly instead.
Results normalize to CIS Kubernetes control assessments; FAIL raises a
finding, PASS is evidence only (§40/§41).

## Health

UNAVAILABLE without the binary; effectively NOT_CONFIGURED on any
non-privileged worker.
