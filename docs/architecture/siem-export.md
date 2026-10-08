# SIEM Export (Prompt 24 §61–§67)

`SiemExportService` converts platform events into the §64 SIEM shape:
event id, timestamp, workspace reference, type, severity, finding
id, asset reference, risk score, CVE/CWE where applicable, status.
No evidence, no secrets — ever.

Event types (§62): `FINDING_CREATED`, `FINDING_VERIFIED`,
`CRITICAL_FINDING`, `KEV_DETECTED`, `ASSET_EXPOSURE_CHANGED`,
`AUTHENTICATION_SECURITY_EVENT`, `SCAN_FAILED`, `RISK_INCREASED`,
`SLA_OVERDUE`, `POLICY_VIOLATION`. Formats: JSON, CEF, LEEF (§63).

Export is asynchronous through the outbox with queue + retry +
backoff + dead-letter (§65/§66): **a SIEM outage never blocks scan
completion** — the producing workflow finishes and the event waits
in the outbox. The event id is stable across retries so the
destination can deduplicate (§67).
