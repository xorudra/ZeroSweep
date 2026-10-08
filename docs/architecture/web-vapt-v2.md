# Web VAPT V2 (Prompt 32)

V2 deepens the Prompt 5–7 web engines on the **same canonical models** —
`Target`, `Asset`, `Endpoint`, `EndpointParameter`, `EndpointForm`,
`Finding`. Nothing was rebuilt in parallel. The V2 additions are planning
and governance records (`WebVaptTarget`, `WebVaptScanPlan`,
`ScanScopeSnapshot`, `WebVaptPreflightResult`, `WebVaptCoverage`,
`WebToolHealth`, `WebScanSession`, `WebVaptEvidence`) plus the capability
registry in `packages/security-sdk/src/webvapt/`.

## Shape

- A **WebVaptTarget** binds an existing VERIFIED asset + parent Target to
  an APPROVED assessment (the active authorization). Creation is refused
  without both (§6).
- A **scan plan** is generated before anything runs: profile stages,
  allowed tools, §16-gated HIGH modules (blocked ones are listed with
  reasons, never silently dropped), a budget clamped to the platform
  ceiling, and an immutable scope snapshot (SHA-256 over sorted
  origins/hosts/exclusions).
- **Preflight** evaluates real authorization facts (verification,
  approval, verification expiry) plus probe observations through a
  transport seam. Where no probe transport is wired, the transport
  reports `NOT_CONFIGURED` and the verdict is BLOCKED — reachability is
  never assumed (§7/§8).
- Execution flows through the canonical assessment → scan pipeline and
  the shared ToolRegistry; the V2 adapters (Dalfox, XSStrike, SQLmap,
  Commix, SSTImap, WPScan) register alongside every other family in the
  worker. Findings come only from tool output through parsing →
  normalization → correlation → risk, exactly as in V1.

## Profiles (§122)

`WEB_PASSIVE`, `WEB_SAFE` (the baseline), `WEB_STANDARD`, `API_SAFE`,
`API_STANDARD`, `TLS_ONLY`, `CONTENT_DISCOVERY`, `TARGETED_VERIFICATION`.
Named profiles never contain HIGH-risk tools; HIGH modules join a plan
only via an explicit request that passes the §16 gate (explicit profile +
active authorization + `RUN_HIGH_RISK_WEB_TESTS` + recorded approval).

## Honesty rules

- Parser failure ⇒ partial/error, never clean (§145/§188).
- Budget exhaustion ⇒ graceful stop, `COMPLETED_WITH_GAPS` (§186).
- Coverage is measured; a null ratio means "not measured", and no output
  claims a target is "100% secure" (§148).
