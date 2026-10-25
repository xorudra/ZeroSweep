# Kubernetes Credential Model (Prompt 13 §32/§33)

ZeroSweep stores **references, never credentials**, for clusters:

- A cluster registration carries an API-server *reference* (a name the
  deployment maps to an endpoint out of band) and a credential
  *reference name*. The registration schema is strict: a kubeconfig
  blob, token, password or client key field is refused by validation,
  not merely ignored.
- The credential a worker uses is resolved inside the worker boundary
  from the deployment's secret store by reference name, for the
  duration of one inventory operation. It never enters a queue payload,
  a scan plan, a log line, an event, or an API response (audits record
  the cluster name and action only, §111).
- The registered service account is **read-only and least-privilege**
  (get/list/watch on inventory resources). Cluster-admin is never the
  default; posture checks that detect cluster-admin bindings flag them
  as CRITICAL findings — including ZeroSweep's own service account if
  it were ever over-privileged.
- Service-account tokens are never retrieved or used by posture code
  (§67): automount configuration is assessed from workload metadata,
  not by reading a token.
- Cluster API access is bounded (§82): read-only verbs only, paginated
  requests, bounded concurrency, and backoff on API errors. The
  transport contract exposes no write method, so no code path can
  mutate a cluster through the connector.
