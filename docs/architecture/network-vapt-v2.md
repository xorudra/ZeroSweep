# Network VAPT V2 (Prompt 33)

Advanced Network VAPT V2 deepens the Prompt 10 network engine; it does
not replace it. The Prompt 10 adapters (Nmap, Naabu, RustScan, Masscan,
Netdiscover, arp-scan, tcpdump, tshark), the NSE script catalog, the
CIDR policy, the port profiles and the safe service checks remain the
execution substrate. V2 adds the governed product layer on top:

- **Targets** (`NetworkVaptTarget`) bind a VERIFIED parent target to an
  APPROVED assessment — the authorization record. Target values are
  normalized (IPv4/IPv6/CIDR/hostname/asset-group) before scope exists;
  injection-shaped input is rejected as hostile data.
- **Preflight** (`NetworkVaptPreflightService` logic in the SDK)
  evaluates real authorization facts; reachability/worker facts
  traverse a transport seam that is NOT_CONFIGURED in this deployment,
  so verdicts are honestly TOOL_UNAVAILABLE — never assumed READY.
- **Plans** freeze an immutable `ScanScopeSnapshot`, a platform-clamped
  budget, the exact NSE script selection, and every governance refusal
  (Masscan gate, FULL_TCP, blocked NSE categories, credentialed-scan
  rules) as visible `blockedItems`.
- **Pipeline**: PREFLIGHT → HOST_DISCOVERY → PORT_DISCOVERY →
  SERVICE_ENUMERATION → PROTOCOL_ANALYSIS → VULNERABILITY_ASSESSMENT →
  NORMALIZATION → CORRELATION → RISK → REMEDIATION → REPORT. Scans
  materialize only on a READY preflight; nothing is fabricated.
- **Findings** flow through the Prompt 11 scanner parsers →
  CanonicalFindingCandidate normalization (plugin provenance, secret
  redaction) → multi-scanner correlation (one canonical finding,
  preserved disagreement) → Risk Engine V3 signals → Prompt 31
  remediation lifecycle.

Modules: SDK `packages/security-sdk/src/netvapt/`, API
`apps/api/src/modules/network-vapt/`, UI `apps/web/src/app/vapt/network/`.
