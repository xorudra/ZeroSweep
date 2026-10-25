# Product Feature Matrix (Prompt 40 §274/§275)

Authoritative source: the Product Feature Registry in
`@zerosweep/security-sdk` (`PRODUCT_FEATURE_REGISTRY`) and each plan
version's `PlanEntitlement` rows. This matrix describes the EXAMPLE
plans (§256); deployments may define their own plans — entitlements
are data, not code.

| Feature | Community | Trial | SaaS Starter | SaaS Professional | Enterprise | Self-Hosted |
|---|---|---|---|---|---|---|
| ASSET_DISCOVERY | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WEB_VAPT | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| API_VAPT | – | ✓ | ✓ | ✓ | ✓ | ✓ |
| NETWORK_VAPT | – | ✓ | – | ✓ | ✓ | ✓ |
| CLOUD_SECURITY | – | ✓ | – | ✓ | ✓ | ✓ |
| CONTAINER_SECURITY | – | ✓ | – | ✓ | ✓ | ✓ |
| KUBERNETES_SECURITY | – | – | – | ✓ | ✓ | ✓ |
| SAST | – | ✓ | ✓ | ✓ | ✓ | ✓ |
| SCA | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MOBILE_VAPT | – | – | – | ✓ | ✓ | ✓ |
| BINARY_ANALYSIS | – | – | – | ✓ | ✓ | ✓ |
| AI_COPILOT | – | ✓ (metered) | – | ✓ (metered) | ✓ (metered) | ✓ (metered) |
| REPORTING | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CLIENT_PORTAL | – | ✓ | ✓ | ✓ | ✓ | ✓ |
| INTEGRATIONS | – | ✓ | ✓ | ✓ | ✓ | ✓ |
| SSO | – | – | – | – | ✓ | ✓ |
| AUDIT_EXPORT | – | – | – | ✓ | ✓ | ✓ |
| ADVANCED_RBAC | – | – | – | ✓ | ✓ | ✓ |
| CUSTOM_REPORTS | – | – | – | ✓ | ✓ | ✓ |

Safety controls are NOT features and never appear in this matrix:
tenant isolation, authorization, target verification, scope
enforcement, scanner safety policy, audit logging and hard platform
ceilings apply identically on every plan (§16).

A feature shown as entitled can still be unavailable in a deployment
(commercial tool unconfigured, worker offline) — the effective
capability state says so explicitly (§119–§121).
