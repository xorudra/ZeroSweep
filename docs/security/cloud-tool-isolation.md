# Cloud Tool Isolation & Command Safety (Prompt 34 §106–§109)

Cloud/container/Kubernetes tools run as governed tool jobs in the
Prompt 3/4 worker plane — never in the API process.

- **Isolation (§106):** dedicated job type and queue, separate
  worker pool, minimal filesystem (read-only inputs), NO cloud
  metadata endpoint access from the job network namespace, no
  inherited host credentials, CPU/memory/time bounds.
- **Command safety (§107):** commands are built as argv arrays from
  typed parameters (`buildToolArgv`) — never shell strings. Values
  containing shell metacharacters (`; & | $ \` > <` newlines) and
  flag-like values where a value is expected are REJECTED, proven by
  the §161 injection test. Raw Steampipe SQL is rejected the same
  way (§25): only approved pack query ids exist.
- **Credentials (§108):** injected per job from Secrets Management
  via TTL-bound leases, scoped to the one account/cluster, revoked
  at job end; never present in argv, environment dumps or logs.
- **Egress (§109):** jobs may reach only the target provider/cluster
  endpoints for the job's scope; all other egress is denied by the
  worker network policy.
- docker.sock is never mounted anywhere in this plane
  (`docker-socket-security.md`); privileged host checks stay gated
  to PRIVILEGED_HOST workers (Prompt 13).
