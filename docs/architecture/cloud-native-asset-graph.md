# Cloud-Native Asset Graph (Prompt 13 §52/§53)

The cloud-native engines connect four inventories into one graph:

```
SourceSnapshot ──(Checkov / Kubescape manifest scans)──▶ InfrastructureManifest
        │                                                        │ same control,
        │                                                        │ same resource
        ▼                                                        ▼
ContainerImage ──(digest binding)──▶ KubernetesWorkload ──▶ KubernetesCluster
        │                                                        │
        └── SoftwareComponent (SBOM inventory)                   └── RuntimeSecurityEvent
```

- **Source → cluster (§52):** a manifest finding (static origin) and a
  live cluster finding share the configuration fingerprint
  (namespace, kind, name, container, control); correlation keeps one
  canonical finding with both observations.
- **Image → workload (§53):** a workload's image is matched to the image
  inventory by digest at full confidence; tag-only matches are recorded
  at reduced confidence, because a tag is mutable.
- **Image → components:** Syft inventories bind to the image row, so an
  image CVE can be traced to the exact package and layer metadata, and a
  workload can be traced to the vulnerable image it runs.
- **Cluster → runtime:** runtime events attach to clusters/workloads as
  detection context (§63) — context raises triage priority, never a
  vulnerability claim.

Every edge is derived from recorded observations (scanner output,
inventory payloads, snapshot records). Nothing in the graph is inferred
from names alone, and discovered assets never expand an assessment's
scope.
