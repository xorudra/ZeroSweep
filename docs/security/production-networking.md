# Production Networking (Prompt 38 §53–§57, §86–§94)

- Public entry is exactly one TLS-terminating ingress → web + API.
  PostgreSQL, Redis, object storage admin, metrics and worker control
  ports are private (§54–§56); the compose profile binds admin ports
  to loopback, Kubernetes uses NetworkPolicies (§57).
- Internal service traffic stays on the private network; TLS is
  required for DB/Redis when endpoints leave the node
  (`DATABASE_REQUIRE_TLS` / `REDIS_REQUIRE_TLS`, enforced by the
  production config gate).
- Scanner egress is governed by the authorization architecture
  (§88/§89): workers reach approved targets only; metadata endpoints
  are unreachable from scanner pods by policy + network rules.
- DNS, NTP and certificate automation are operator infrastructure;
  certificate expiry is alerted 14 days out (§121).
