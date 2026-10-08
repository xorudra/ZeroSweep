# SIEM Integration (Prompt 24 §61–§67)

See `docs/architecture/siem-export.md` for the full model. Summary:
event types FINDING_CREATED, FINDING_VERIFIED, CRITICAL_FINDING,
KEV_DETECTED, ASSET_EXPOSURE_CHANGED,
AUTHENTICATION_SECURITY_EVENT, SCAN_FAILED, RISK_INCREASED,
SLA_OVERDUE, POLICY_VIOLATION; formats JSON / CEF / LEEF; export is
queued with retries and dead-lettering, so collector outages never
block scans (§130); event ids are stable for destination-side
deduplication (§67). No evidence or secret material is exported.
