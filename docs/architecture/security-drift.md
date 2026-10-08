# Security Drift (Prompt 22 §33–§50)

Drift is computed by `DriftService` over the two most recent
immutable snapshots per workspace, and over stored intelligence for
risk drift. All comparisons are pure SDK functions
(`packages/security-sdk/src/continuous/diff.ts`) so they are unit
tested without a database.

## Asset drift (§33)

NEW / REMOVED / CHANGED / REAPPEARED (an asset absent from the
previous snapshot but present in an older one). Field-level changes:
exposure, ports opened/closed, services added/changed, endpoint
count, criticality, scope status.

## Attack-surface changes (§34–§46)

Surface events are persisted as `AttackSurfaceChange` rows:
NEW_DOMAIN, NEW_SUBDOMAIN, NEW_HOST, NEW_PORT, NEW_SERVICE,
NEW_WEB_APP, NEW_API, NEW_CLOUD_RESOURCE, NEW_PUBLIC_RESOURCE,
NEW_REPOSITORY, NEW_CONTAINER_IMAGE, EXPOSURE_CHANGED,
SERVICE_CHANGED, ENDPOINT_CHANGED, ASSET_REMOVED. The per-domain
sections (§37–§46: service, web, API, cloud, Kubernetes, source,
mobile, binary, identity, wireless) feed the same comparison shape;
wireless drift reuses the Prompt 19 comparison on HMAC-pseudonymized
stations and never de-pseudonymizes.

Rules that never bend:

- **New assets are DISCOVERED, never authorized** (§35). A drift
  event cannot expand scope or create a target.
- **Exposure PRIVATE → INTERNET_FACING is HIGH priority** (§36),
  emitted as both EXPOSURE_CHANGED and NEW_PUBLIC_RESOURCE.

## Finding drift (§47)

NEW / RESOLVED / REOPENED (a finding whose lifecycle was RESOLVED
and is observed again) / SEVERITY_CHANGED / PRIORITY_CHANGED /
VERIFICATION_CHANGED / RISK_CHANGED (score movement ≥ 10 points).

## Risk drift (§48–§50)

Intelligence movement is evaluated against each finding's stored
intel snapshot: KEV_ADDED, EPSS_INCREASED (≥ +0.1),
CVSS_CHANGED. Affected findings — and only those — are re-scored
with Risk Engine V3 from stored data (severity, effective CVSS,
EPSS, KEV, asset criticality, verification, age). No scanner runs
for intelligence movement.
