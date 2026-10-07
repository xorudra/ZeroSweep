# kube-hunter

**Adapter:** `KubeHunterAdapter`, executable `kube-hunter`,
capabilities `KUBERNETES_SECURITY_DISCOVERY`,
`KUBERNETES_POSTURE_TESTING`. Classification: STATIC_ANALYSIS with a
governed check policy (§42/§43). Worker: `CONTAINER_ANALYSIS`.

Every kube-hunter check is classified in code: SAFE (passive reads),
REVIEW_REQUIRED (needs a separately approved review — never enabled by
scan configuration), INTRUSIVE, DISABLED (pod execution, privilege
escalation, container escape, credential access — these can never run).
Automated scans pass `--remote` discovery in passive mode only; the
`--active` flag exists in no plan the adapter can produce. Unlisted
checks fail closed as REVIEW_REQUIRED.

## Health

UNAVAILABLE when the binary is absent from the worker host.
