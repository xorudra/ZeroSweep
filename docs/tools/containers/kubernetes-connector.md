# Kubernetes Connector

**Adapter:** `KubernetesConnector`, connector (no executable),
capabilities `CLUSTER_INVENTORY`, `RESOURCE_INVENTORY`,
`POSTURE_ASSESSMENT`. Classification: CONNECTOR. Worker: any worker
with cluster transport provisioned.

Read-only inventory + posture for registered clusters (§32–§38):
cluster records resolve from the platform registry by reference;
credentials resolve inside the worker boundary by reference name and
never enter plans, payloads or logs. The transport contract has no
write method and returns secret METADATA counts only — secret values
cannot be retrieved through it (§36). Access is bounded (§82):
read-only verbs, pagination, bounded concurrency, backoff.

Plan-time health: HEALTHY exactly when the workspace has a registered
cluster; otherwise NOT_CONFIGURED and inventory stages plan empty
rather than simulated. On this build's workers no live cluster
transport is provisioned, so execution reports UNAVAILABLE honestly
rather than fabricating inventory.
