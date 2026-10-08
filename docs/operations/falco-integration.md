# Falco Integration (Prompt 34 §91–§96)

## Wiring

Falco runs on the cluster (outside DSRclone). Events reach the
platform through the governed ingestion path into
`RuntimeSecurityEvent` (the Prompt 13 Falco connector contract:
rule, priority, namespace, pod, container, host, output fields).
Priorities pass through Falco's vocabulary: EMERGENCY, ALERT,
CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG.

## Operating rules

- Falco is DETECTION. DSRclone never kills/restarts workloads and
  runs no admission webhook in response (§96).
- Correlation (Kubernetes Security page → Correlate) links the event
  to workload/image/findings and, for HIGH-confidence
  EMERGENCY/ALERT/CRITICAL signals, raises ONE SOC alert via the
  governed raise path (fingerprint-deduped, §141).
- A runtime event on a vulnerable image raises contextual risk only;
  scanner severity is unchanged (§95). Do not close findings on
  runtime evidence alone — verification stays manifest/benchmark/
  rescan based (§123).
- If events stop arriving, coverage shows the runtime-telemetry gap
  (TOOL_UNAVAILABLE) — the cluster is unmonitored, not "quiet".
