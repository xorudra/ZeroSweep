# Kubernetes Security (Prompt 13)

Clusters are registered **by reference** (§32/§33): an API-server
reference name, a credential REFERENCE name, and the name of a
least-privilege read-only service account. No kubeconfig, token or
certificate is accepted, stored or returned by any API. There is no
cluster-admin default anywhere in the platform.

## Inventory and posture (§34–§38)

The Kubernetes Connector performs `CLUSTER_INVENTORY`,
`RESOURCE_INVENTORY` and `POSTURE_ASSESSMENT` over inventory metadata:
namespaces, nodes, workloads, services, ingresses, NetworkPolicies,
service accounts, Roles and Bindings. **Secret values are never
retrieved** (§36) — the transport contract carries a secret metadata
count, and no method on it can return a value.

The posture engine flags, as configuration findings: privileged
containers (KSV-0014), hostPath volumes, dangerous capabilities
(SYS_ADMIN/NET_ADMIN/ALL), containers that may run as root, host
network/PID/IPC sharing, service-account token automount, default
service accounts, unpinned/mutable image references, missing resource
limits, and cluster-admin or wildcard RBAC bindings. A namespace with
exposed workloads and no NetworkPolicy raises a finding; an internal
namespace without one is context, not a vulnerability (§66). An
end-of-life Kubernetes version produces a POTENTIAL_EXPOSURE-style
assessment, never a CVE claim (§73).

## Governed tools (§39–§47)

- **kube-bench** — CIS Kubernetes Benchmark, `INTERNAL_PRIVILEGED` like
  Docker Bench: approved cluster + dedicated privileged worker only.
- **Kubescape** — posture + manifest analysis with compliance mapping;
  configuration findings dedupe against the posture engine by identity.
- **kube-hunter** — every check is classified SAFE / REVIEW_REQUIRED /
  INTRUSIVE / DISABLED. Automated runs are passive-discovery only;
  INTRUSIVE and DISABLED checks (pod execution, privilege escalation,
  credential access) can never be enabled by scan configuration.
- **Checkov** — static IaC/manifest/Dockerfile/Helm analysis reusing the
  source-security intake discipline; IaC and Helm hooks are never
  executed.

## Static vs live (§51–§54, §103)

Manifest findings carry origin `STATIC_CONFIGURATION_FINDING`; cluster
findings carry `LIVE_CLUSTER_FINDING`. When both describe the same
control on the same resource identity (namespace/kind/name/container/
control fingerprint), correlation merges them into one canonical finding
that preserves BOTH observations. Image→workload correlation binds by
digest; a tag-only match is recorded at lower confidence.
