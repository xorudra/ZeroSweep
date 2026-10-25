# Kubernetes Deployment (Prompt 38 §5, §212–§217)

Two equivalent paths over the same security semantics:

- **Kustomize (canonical):** `kubectl apply -k deploy/kubernetes/overlays/production`
  (base carries Deployments, Services, ConfigMap, HPA, PDB,
  NetworkPolicies, quotas).
- **Helm:** `helm install zerosweep deploy/helm/zerosweep -f values.yaml`
  — values are schema-validated (`values.schema.json`); the chart
  consumes an EXISTING Secret (`existingSecret`) and never renders
  secret values.

Managed PostgreSQL/Redis/S3 are external (§215–§217): point the
ConfigMap endpoints + secret at them and skip bundled data services.
Post-install: confirm migrations applied (`/admin/platform` release
panel), run the smoke in `scripts/local-stack/smoke.mjs` shape against
the ingress, and record the deployment in the admin plane.
