# Falco (connector)

**Component:** `FalcoConnector`, connector (no executable), capability
`RUNTIME_SECURITY_EVENTS`. Classification: CONNECTOR (§57).

Falco is a runtime sensor that runs outside ZeroSweep; ZeroSweep never
deploys or configures it. Detections arrive through the trusted
ingestion path, are validated and sanitized (§60 — escapes, control
characters, forged log lines, secret-shaped substrings), and persist as
`RuntimeSecurityEvent` rows. Events are detections, not
vulnerabilities; posture/KEV correlation adds triage context and never
claims exploitation (§63). Ordinary users cannot upload arbitrary
Falco rules through ingestion (§61) — payloads name existing rules.

## Health

NOT_CONFIGURED until a sensor feed is configured for the deployment.
