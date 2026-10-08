# Product Analytics & Telemetry (Prompt 40 §141–§147)

- `ProductAnalyticsService` records a CLOSED set of aggregate product
  events (signup, onboarding steps, first scan/report, plan changes,
  trial lifecycle, quota hits).
- Properties pass a sanitizer that drops anything resembling targets,
  URLs, credentials, tokens, evidence or finding payloads (§142) —
  analytics NEVER contains security content.
- Telemetry is **off by default** (`PRODUCT_TELEMETRY_ENABLED=false`),
  configurable by the deployment operator, and documented here (§146).
- Customer health indicators, where shown, are operational usage
  signals — they are NOT a security score and are never presented as
  one (§147).
