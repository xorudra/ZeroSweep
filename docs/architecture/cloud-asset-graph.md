# Cloud Asset Graph (Prompt 14 §15/§85)

Every inventoried cloud resource is also an **asset**: it carries
provider, region and service identity (`resourceType` such as
`AWS_S3_BUCKET`, the provider resource id — ARN / Azure resource id /
GCP full resource name —, name, exposure class, criticality and
sources). Resources discovered outside the account scope are recorded
with `scopeStatus = OUT_OF_SCOPE` — recorded, never promoted, never
assessed (§5/§15). A resource that disappears from inventory is marked
`NOT_SEEN`/`REMOVED`; historical records are never hard-deleted (§20).

## Relationships (§37)

Edges (`CloudRelationship`) exist **only where a provider response or
a governed check supplied evidence** — the graph never speculates.
Kinds include `CONTAINS`, `ATTACHED_TO`, `ASSUMES`, `MEMBER_OF`,
`GRANTS`, `ROUTES_TO`, `EXPOSES`, `RUNS`, `USES_IMAGE`, `MAPS_TO`
between accounts, regions, networks, resources, identities, policies,
workloads, images, clusters, services and endpoints. Serverless
identity references and cluster/registry links from the inventory are
the primary edge sources; the AWS EKS / Azure AKS / GCP GKE resources
link the cloud estate to the Phase 13 Kubernetes/container estate
(§98).

## Risk paths (§66/§67)

A risk path is a **defensive model** of exposure — for example
*public network rule → instance → assumed role → sensitive bucket* —
assembled from evidence-backed edges plus canonical findings. It is
never executed, and privilege escalation along a path is never
attempted. Each path records its steps, a confidence
(LOW/MEDIUM/HIGH) and the finding ids that support it.

## API

`GET /cloud/graph` (edges) and `GET /cloud/risk-paths`, both under the
`VIEW_CLOUD_GRAPH` permission; the GUI renders them at
`/cloud-security/graph`.
