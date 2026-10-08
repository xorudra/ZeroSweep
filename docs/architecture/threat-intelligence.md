# Threat Intelligence (Prompt 28 §54–§69)

## Model

`ThreatIntelSource` (with trust level and transport status),
`ThreatIndicator` (IP, DOMAIN, URL, FILE_HASH, EMAIL_DOMAIN,
CERTIFICATE_FINGERPRINT), `IndicatorObservation` (per-source
provenance), `IndicatorMatch`, and `ThreatIntelFeedSync`.

## Ingestion (§59–§62)

Live feed transports are deliberately unwired: a sync attempt
records `NOT_CONFIGURED` and imports nothing. The ingestion path
is recorded fixture/manual import. STIX bundles are parsed
defensively (object-type allowlist, 5000-object and 5 MB caps,
indicator patterns extracted as strings — never evaluated). Every
imported indicator keeps per-source observations, so provenance
("which source said this, when, with what confidence") survives
dedupe.

## Confidence & expiry (§63/§66)

Confidence is deterministic: source trust × recency factor, plus a
bounded corroboration bonus for independent sources; an analyst
value overrides. Statuses: `ACTIVE`, `EXPIRED`, `REVOKED`,
`FALSE_POSITIVE`. At match time an indicator is active for
detection only if its status and validity window allow it;
expired indicators can still produce historical matches when
policy allows, flagged as such.

## Matching (§64/§65/§69)

Candidate values come from the telemetry event itself (source IP,
domain, URL, file hash, email domain). A match records the
indicator's provenance and its confidence at match time. An alert
is raised only for an active indicator with meaningful confidence
(≥ 40), and its text cites the provenance as enrichment context.
One low-confidence feed can never classify an event malicious on
its own, and a match is never presented as attribution.

## Privacy (§68)

Internal telemetry, assets and findings are never submitted to
external intelligence providers. There is no outbound lookup path
in the module at all.
