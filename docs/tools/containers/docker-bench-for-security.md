# Docker Bench for Security

**Adapter:** `DockerBenchAdapter`, executable `docker-bench-security`,
capabilities `DOCKER_CIS_ASSESSMENT`, `DOCKER_HOST_CONFIGURATION`,
`COMPLIANCE_ASSESSMENT`. Classification: **INTERNAL_PRIVILEGED** (§28).
Worker: `PRIVILEGED_HOST` only.

CIS Docker Benchmark checks against an explicitly approved Docker host.
The worker executor refuses the adapter unless the worker holds the
`PRIVILEGED_HOST_ASSESSMENT` capability (granted only to
`PRIVILEGED_HOST`-type workers that declare it); on any other worker
the stage degrades with `UNAVAILABLE_FOR_WORKER`. Results normalize to
CIS Docker control assessments — PASS is evidence only, WARN/FAIL raise
findings (§31). ZeroSweep never mounts a Docker socket to run it
(§30/§106).

## Health

UNAVAILABLE without the binary; effectively NOT_CONFIGURED on any
non-privileged worker.
