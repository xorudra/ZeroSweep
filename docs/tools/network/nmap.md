# Nmap (network discovery, service detection, safe checks)

**Adapter:** `NmapAdapter` (`packages/security-sdk/src/network/`),
executable `nmap`, stages `HOST_DISCOVERY`, `PORT_DISCOVERY`,
`SERVICE_DETECTION`, `SAFE_NETWORK_CHECKS`. Risk: MODERATE. Worker:
`NETWORK_EXTERNAL` (or `NETWORK_INTERNAL` for internal profiles).

One adapter, four stage modes — the worker derives the mode from the
stage and the port profile + NSE approvals from the assessment
profile. Clients supply none of it.

## Governance

- Commands are built **only** from validated typed configuration
  (`scanMode`, `portProfile`, `customPorts`, `hostDiscoveryMode`,
  `versionIntensity`, `osDetection`, `approvedScriptIds`, `rateLimit`,
  `timingProfile` capped at T4, `udpScan`). There is no raw-argument
  field anywhere (§13).
- **NSE scripts** follow `NmapScriptPolicy`: a curated versioned
  catalog classifies scripts SAFE / REVIEW_REQUIRED / INTRUSIVE /
  DISABLED. Only SAFE + admin-approved REVIEW_REQUIRED scripts are
  ever named — individually, never as a category expression. `default
  + vuln + brute + exploit` style invocations do not exist (§14).
- XML output is parsed as hostile input (`xml-lite`): DTD subsets and
  external entities are rejected; size, depth and node counts capped.
- OS detection produces a **hint + confidence**, never a fact (§35).
  CPEs are stored only when Nmap reported them (§34).
- Target tokens with shell metacharacters or option-like leading
  dashes are rejected before plan construction (§82).

## Health

Reports UNAVAILABLE when the `nmap` binary is absent from the worker
host — stages degrade; nothing is faked.
