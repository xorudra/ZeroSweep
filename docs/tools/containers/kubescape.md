# Kubescape

**Adapter:** `KubescapeAdapter`, executable `kubescape`, capabilities
`KUBERNETES_POSTURE`, `MANIFEST_ANALYSIS`, `COMPLIANCE_ASSESSMENT`.
Classification: STATIC_ANALYSIS. Worker: `CONTAINER_ANALYSIS`.

Two governed modes: manifest analysis (static origin — YAML treated as
hostile input, §49) and cluster posture (live origin) over the
registered cluster connection. Results map to compliance frameworks
(the catalog's control IDs) and dedupe against the platform posture
engine by configuration fingerprint (§45/§54) — the same control on
the same resource is one canonical finding with both observations.

## Health

UNAVAILABLE when the binary is absent from the worker host.
