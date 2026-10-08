# Product Configuration (Prompt 40 §253–§255)

All product behavior is deployment configuration — see
`config/product.example.env` for the annotated template.

| Variable | Meaning | Default |
|---|---|---|
| `PRODUCT_MODE` | COMMUNITY / SELF_HOSTED / SAAS / ENTERPRISE (§3) | SELF_HOSTED |
| `RELEASE_VERSION` | Release identity in health/diagnostics | 1.0.0 |
| `PRODUCT_BILLING_PROVIDER` | unset = NOT_CONFIGURED; `test` = test provider (refused in production) | unset |
| `PRODUCT_BILLING_WEBHOOK_SECRET` | HMAC secret for webhook verification | unset |
| `PRODUCT_LICENSE_PUBLIC_KEY` | Ed25519 public key (PEM) enabling license verification | unset |
| `PRODUCT_LICENSE_GRACE_DAYS` | Post-expiry grace for paid capabilities (§35) | 14 |
| `PRODUCT_TRIAL_DAYS` | Default trial length (§54) | 14 |
| `PRODUCT_PLATFORM_ADMIN_EMAILS` | Platform-admin bootstrap list (§96) | unset |
| `PRODUCT_TELEMETRY_ENABLED` | Aggregate product analytics (§145) | false |
| `PRODUCT_UPDATE_CHECKS_ENABLED` | Signed update-metadata checks (§187) | false |

## SaaS vs self-hosted

- **SaaS mode**: signup provisions organizations with the TRIAL plan;
  billing, when configured, drives subscription state (§17/§18).
- **Self-hosted mode**: signup provisions the SELF_HOSTED plan;
  entitlements can additionally come from a signed product license
  (§28). No billing provider is required.
- Mode is read from trusted deployment configuration only — a tenant
  request can never change it (§4).
