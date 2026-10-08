# Runtime Security — Falco (Prompt 34 §91–§96)

Falco is a DETECTION and SOC signal source (§92). It is never
enforcement: DSRclone does not kill, delete or restart workloads in
response to an event (§96), and it operates no admission webhook.

## Event model (§93)

Events land on the Prompt 13 `RuntimeSecurityEvent` model (rule,
priority, namespace, pod, container, host, timestamps, labels,
output fields). Prompt 34 adds `RuntimeEventCorrelation`.

## Correlation (§94/§95)

`correlateRuntimeEvent` links event → pod → workload → image →
known findings. Confidence is LOW (event only), MEDIUM (workload +
image resolved), HIGH (a known CVE finding exists on that image).
HIGH-confidence events at EMERGENCY/ALERT/CRITICAL priority produce
a SOC alert recommendation; the alert is raised through the single
governed Prompt 28 raise path with fingerprint
`falco:<cluster>:<rule>:<workload>`, so re-correlation never
double-alerts (§141).

Correlation may raise CONTEXTUAL RISK only. It never changes a
finding's scanner severity, never asserts the CVE was exploited,
and never triggers a workload action. The distinction between a
detection, a vulnerable workload and an exploited workload is
preserved in the UI copy.
