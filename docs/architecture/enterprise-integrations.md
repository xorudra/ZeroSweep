# Enterprise Integrations — Architecture (Prompt 24)

The integration registry lives on the existing `Integration` model
(extended in place, never replaced): each row is one provider instance
in one workspace, with `status` (§5), `capabilities`, non-secret
`configuration`, and a `secretReference`. **Credentials exist only as
references** — the database has no column capable of holding a token,
and the create/update schemas reject secret-shaped values outright.

Every provider implements the SDK `EnterpriseIntegrationConnector`
contract (§6): `healthCheck`, `capabilities`, `validateConfiguration`,
`testConnection`, `sync`, `handleWebhook`, `rotateCredentialReference`.
All provider HTTP goes through an injected `IntegrationTransport`.
Production wiring returns the deliberately **unconfigured** transport:
health reports `NOT_CONFIGURED`, sync imports nothing, deliveries are
recorded `NOT_CONFIGURED` — never fabricated success. Fixture
transports (recorded payloads) verify behavior in tests.

## RBAC (§9)
`VIEW_INTEGRATIONS` (all roles), `CREATE/EDIT/DELETE_INTEGRATION` and
`MANAGE_INTEGRATION_SECRETS` (OWNER/ADMIN), repository/ticketing/
messaging management (leads), `MANAGE_SIEM_INTEGRATIONS` (admins).
Secret management means managing references; no permission can return
a secret value because none is stored.

## Lifecycle
Create → PENDING → test connection → CONNECTED / DEGRADED /
AUTHENTICATION_FAILED per probe. Provider failure degrades the
integration only; the platform is never blocked (§104). Deletion stops
sync/delivery and drops the reference with the row, while historical
findings, tickets and audit records are preserved (§103).
