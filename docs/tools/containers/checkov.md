# Checkov

**Adapter:** `CheckovAdapter`, executable `checkov`, capabilities
`IAC_SECURITY`, `KUBERNETES_MANIFEST_SECURITY`, `DOCKERFILE_SECURITY`,
`HELM_SECURITY`. Classification: STATIC_ANALYSIS. Workers:
`CONTAINER_ANALYSIS` / source workers.

Static analysis of IaC, Kubernetes manifests, Dockerfiles and Helm
charts over registered content (§46/§47), reusing the source-security
intake discipline: files are data, path safety is enforced, and **IaC
is never executed** — no terraform apply, no Helm template hooks, no
chart scripts. Findings carry the file + line range and the resource
identity (`kind.namespace.name`) so static findings can correlate with
live cluster findings (§51).

## Health

UNAVAILABLE when the binary is absent from the worker host.
