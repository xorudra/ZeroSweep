# Tool Adapter SDK (Prompt 3)

The Universal Security Tool Adapter SDK (`packages/security-sdk`) is how
ZeroSweep integrates 100+ security tools without hardcoding any scanner into
the API or the orchestration engine. The orchestrator only ever talks to the
`SecurityToolAdapter` contract; everything tool-specific lives behind it.

## Adapter lifecycle

`validateConfiguration → validateTarget → validateScope → checkAvailability →
prepare → buildExecutionPlan → execute → parse → normalize → cleanup`, plus
`healthCheck` at any time. `BaseSecurityToolAdapter` provides the shared
gates: target-type compatibility, the SSRF/format target gate for host-based
targets, and configuration validation against the adapter's declared
`inputSchema`.

## No raw command API

There is deliberately **no** endpoint, field or config key that carries a
command. Only trusted adapter code builds an `ExecutionPlan`
(`executable` + validated argument array + secret *references*). User input
arrives as individual arguments validated against the input schema; a config
key named `command`/`shell`/`args` etc. is rejected by validation and covered
by tests. Future workers execute plans with `shell=false` semantics inside
containers described by `ContainerExecutionSpec` (non-root, read-only root
filesystem, no privileged mode, no host networking, no Docker socket,
`dropCapabilities: ["ALL"]`, PID/CPU/memory/timeout limits).

## Registry

`ToolRegistry` holds code-installed adapters only — no dynamic plugin
uploads. Registration validates metadata (`validateAdapterMetadata`: slug
format, category, capabilities, timeout ordering, RESTRICTED ⇒ approval) and
rejects duplicate slugs *and* ids. Resolution: by slug/id, category,
capability, target type, or a combined query. Multi-category tools keep one
identity; the catalog records a primary category.

## Capabilities & risk model

Tools are selected by **capability** (e.g. `SUBDOMAIN_DISCOVERY`,
`HTTP_PROBING`, `TLS_ANALYSIS`, `SAST`), not by name. Risk levels:
`PASSIVE < LOW < MODERATE < INTRUSIVE < RESTRICTED`. Defaults: PASSIVE may
run after scope checks; LOW needs a verified target; MODERATE needs a
verified target + approved assessment; INTRUSIVE needs explicit approval;
RESTRICTED (credential attacks, exploitation, disruptive tooling) is
disabled by default and never auto-selected from a URL submission.

## Policy engine

`evaluateToolPolicy` runs before ANY execution and returns
`ALLOW | DENY | REQUIRE_APPROVAL` with a reason code: `TARGET_NOT_VERIFIED`,
`TARGET_OUT_OF_SCOPE`, `TOOL_DISABLED`, `ADAPTER_DISABLED`,
`TARGET_TYPE_UNSUPPORTED`, `APPROVAL_REQUIRED`, `CREDENTIAL_REQUIRED`,
`NETWORK_POLICY_DENIED`, `RATE_LIMIT_EXCEEDED`, `CONCURRENCY_LIMIT`,
`TOOL_UNHEALTHY`, `ORGANIZATION_MISMATCH`, `TARGET_BLOCKED`. Any mandatory
failure denies. The worker re-evaluates with trusted database state; the
API never executes tools.

## Target & scope validation

`validateTargetValue` treats targets as pure data: shell metacharacters,
embedded URL credentials, non-http(s) protocols, malformed domains/IPs/
CIDRs are rejected. `blockedTargetReason` (SSRF guard) blocks localhost,
loopback, link-local/cloud-metadata, RFC1918, CGNAT, `0.0.0.0/8`, IPv6
loopback/ULA/link-local by default; private targets need an explicitly
approved internal engagement (policy input). Because hostnames can
re-resolve, workers must call `assertResolvedAddressesSafe` on freshly
resolved addresses immediately before execution (DNS-rebinding guard).
`ScopeMatcher` answers host/IP/port/URL/path questions with exact hosts,
`*.` subdomain rules, CIDRs and exclusions; discovered assets never expand
scope (`isDiscoveredAssetInScope`).

## Network policies

`NO_NETWORK`, `TARGET_ONLY`, `SCOPE_ONLY`, `INTERNET_READ_ONLY`,
`CUSTOM_ALLOWLIST` — declared per adapter, enforced by the worker's
container network mode and re-checked by the policy engine.

## Parsers & normalization

Parsing is separate from execution: `SecurityToolParser` implementations
(JSON, JSONL, minimal XML) produce `NormalizedSecurityResult`
(assets/services/endpoints/technologies/findings/artifacts/metrics) aligned
with the Prisma Finding model. Parsers throw `ParserError`, never raw
exceptions. Findings carry a deterministic SHA-256 `sourceFingerprint`
(tool family, asset, endpoint, parameter, vuln class, CVE/CWE) for later
deduplication — unknown CVE/CWE/CVSS stay unknown, never invented.

## Artifacts & limits

Large output lives in object storage; the database holds `ArtifactMetadata`
only. `enforceOutputLimits` caps stdout/stderr/artifact size/count/total,
`clampTimeout`/`clampRateLimits` clamp every request to adapter and
administrator maximums, and telemetry records counts/timings only — never
secrets or request bodies.

## Health & commercial tools

Health: `UNKNOWN | HEALTHY | DEGRADED | UNAVAILABLE | MISCONFIGURED` — a
health failure is never a finding. Commercial tools (Burp Suite Pro, Nessus,
IDA, Binary Ninja, PlexTrac) are `ADMIN_PROVIDED` connectors: the
administrator supplies installation/license/API access; ZeroSweep does not
redistribute them. Credentials are declared as *requirement references*
(e.g. `SHODAN_API_KEY`) and resolved only inside the worker boundary.

## Catalog status (this phase)

The seed loads 126 catalog tools across all 13 categories as metadata with
disabled catalog adapter rows, plus the two real test adapters
(`MockSecurityAdapter`, `LocalEchoAdapter`) — both network-free, in-process,
zero findings, `mock: true`. **No real scanner is integrated or executed in
Prompt 3**; real adapters arrive in later controlled phases.
