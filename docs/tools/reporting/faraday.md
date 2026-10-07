# Faraday Connector (Prompt 20)

Part of the unified vulnerability-platform connector framework
(sections 40-49). Workspace/vulnerability model; severity names map directly, and host data leaves the platform only when the export policy explicitly allows it.

Configuration is by reference only: register the instance under
Integrations with an endpoint reference, a credential reference
and an endpoint allowlist - never a credential value. Capabilities
depend on licence confirmation in the instance config: community
editions expose import/export; vendor-only APIs stay visibly
unavailable rather than failing silently. The server-side
transport is not wired in this build (health: NOT_CONFIGURED);
imports run from administrator-supplied payloads with preview ->
idempotent commit, and disagreements with local state surface as
conflicts - the external platform is never authoritative.
