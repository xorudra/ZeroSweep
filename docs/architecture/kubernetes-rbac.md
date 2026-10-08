# Kubernetes RBAC (Prompt 34 §76/§77)

Roles, ClusterRoles, RoleBindings and ClusterRoleBindings are
inventoried as DATA (`KubernetesRole`, `KubernetesRoleBinding`):
rule tuples (apiGroups/resources/verbs/resourceNames) and subject
identities (ServiceAccount/User/Group + namespace). Privileges are
analyzed, never used.

## Analysis (`analyzeKubernetesRbac`)

Risks: WILDCARD_PERMISSIONS (`*` in verbs/resources/apiGroups),
CLUSTER_ADMIN_BINDING (binding to cluster-admin or a wildcard
ClusterRole — CRITICAL), DANGEROUS_VERB (impersonate, escalate,
bind, approve), ESCALATION_PRIVILEGE, SECRET_ACCESS (get/list/watch
on secrets), WORKLOAD_CREATION (create on pods/deployments —
workload-creation + token-mount is the classic pod-escape setup).
Every risk names its subject; the graph edges are SUBJECT
—BOUND_TO→ ROLE and ROLE —GRANTS→ RESOURCE.

## Import hygiene (§83/§84)

Subject records carrying token/secret/password/credential-shaped
fields are REFUSED at import (test-asserted). Secret values are
never inventoried — only metadata such as secret names and consuming
workloads — and service-account tokens are never harvested.
