# Threat Intelligence Privacy (Prompt 28 §68)

- **No outbound submission.** Internal telemetry, asset data,
  findings and incident content are never sent to external
  intelligence providers — for lookup, enrichment or "community
  sharing". The module contains no outbound intel call at all.
- **Inbound-only flow.** Intelligence arrives as recorded imports
  under a registered source, with provenance kept per observation.
  Live transports are unwired and report `NOT_CONFIGURED` rather
  than polling anything.
- **Hostile-input handling.** Imports are untrusted input: STIX
  bundles are size- and object-capped, object types are
  allowlisted, patterns are parsed as strings and never evaluated,
  and indicator values are strictly normalized per type before
  storage (§61).
- **Confidence honesty.** An indicator's provenance and confidence
  travel with every match. Expired, revoked and false-positive
  indicators are labelled as such in search and on matches; a
  low-confidence indicator enriches an event but cannot classify
  it malicious alone (§69/§140).
- **Tenant scoping.** Indicators are workspace data (§155): one
  tenant's private intel never leaks into another tenant's
  matches, searches or AI context.
