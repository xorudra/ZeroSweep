# External Integration Security (Prompt 20 section 50)

Vulnerability-platform connectors (DefectDojo, Faraday, Dradis,
PlexTrac, Serpico) store endpoint and credential REFERENCES only -
never values or URLs with credentials. Endpoints must match the
instance allowlist; transports enforce HTTPS, timeouts and rate
limits; every import/export/sync is an audited `IntegrationJob`.
Server-side transports are not wired in this build, so health and
push-sync honestly report NOT_CONFIGURED; imports run from
administrator-supplied payloads. The external platform is never
authoritative: disagreements become conflicts for explicit human
resolution, never silent overwrites.
