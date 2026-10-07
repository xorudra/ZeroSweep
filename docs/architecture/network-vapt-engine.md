# Network VAPT Engine (Prompt 10)

The network layer performs governed host/port/service discovery and
safe, evidence-backed network checks over **verified targets with an
approved scope**. It is built entirely on the existing foundations: the
Tool Adapter SDK lifecycle (Prompt 3), the scan DAG (Prompt 4), the
service inventory (Prompt 5), the findings normalization/correlation/
risk pipeline (Prompt 7) and the tenant/audit model.

## Profiles and pipeline (§8/§25)

Four dedicated profiles (plus `NETWORK_ASSESSMENT`, the
baseline-equivalent name kept from Prompt 4) share one DAG:

`AUTHORIZATION_CHECK → SCOPE_VALIDATION → TARGET_EXPANSION →
HOST_DISCOVERY → PORT_DISCOVERY → SERVICE_DETECTION →
SAFE_NETWORK_CHECKS → NORMALIZATION → CORRELATION → RISK_ANALYSIS →
REPORT_GENERATION`

`NETWORK_DISCOVERY` stops after `SERVICE_DETECTION` (no checks stage).
Profiles differ in depth and policy, never in safety rules:

| Profile | Port profile | NSE set | Notes |
| --- | --- | --- | --- |
| NETWORK_DISCOVERY | WEB_COMMON | — | lightweight inventory |
| NETWORK_BASELINE / NETWORK_ASSESSMENT | COMMON_SERVICES | SAFE only | default posture |
| NETWORK_COMPREHENSIVE | STANDARD | SAFE + admin-approved REVIEW_REQUIRED | OS hinting on |
| NETWORK_INTERNAL | STANDARD | SAFE + admin-approved REVIEW_REQUIRED | internal worker + approved internal engagement required |

The port profile and NSE approvals are **derived by the worker** from
the assessment profile — clients can never supply them, and `FULL_TCP`
is never derived.

## Scope, CIDR policy and protected destinations (§3–§7)

- `NetworkScope` canonicalizes scope rules into include/exclude IPs,
  CIDRs and hostnames; exclusions always win.
- `CidrPolicyService` tiers ranges by effective host count:
  `/32` single → SMALL normal; LARGE → elevated approval; VERY_LARGE →
  administrator; above the hard ceiling (default 65,536 hosts) → DENY.
- Expansion is **bounded**: small ranges materialize as host lists,
  large ones exist only as range chunks (`NetworkScanChunk` rows) —
  the platform never creates millions of target rows (§5/§62).
- Protected destinations (loopback, link-local/metadata, unspecified,
  plus deployment-configured platform-infrastructure CIDRs such as the
  platform's own database/Redis/object-store networks) are denied
  unconditionally. RFC 1918 / CGNAT / ULA destinations require an
  **approved internal engagement** — the same Phase 3 rule, enforced in
  the policy engine and re-checked per resolved address.
- Hostname targets are **re-resolved immediately before execution**
  and every resolved address is re-validated (DNS-rebinding defense,
  §7); one bad address fails the validation.

## Adapters (§12–§24)

Eight adapters on the SDK lifecycle (`packages/security-sdk/src/network/`):
Nmap, Naabu, RustScan, Masscan, Netdiscover, arp-scan, tcpdump, tshark.
Wireshark is **not** an adapter — it is a manual analyst tool whose
authorized capture exports are imported (§46).

- **Nmap** is one adapter whose plan varies by stage (host discovery /
  port scan / service detection / safe checks), built ONLY from typed
  configuration. NSE scripts are governed by `NmapScriptPolicy`
  (see `docs/security/network-scan-policy.md`). XML output is parsed as
  hostile input: no DTD subsets, no external entities, size/depth/node
  caps (`xml-lite`).
- **Naabu / RustScan** are fast port discovery feeding Nmap's deeper
  fingerprinting. RustScan's downstream-command passthrough (`--`) is
  never emitted.
- **Masscan** is capability-isolated (`HIGH_SPEED_PORT_DISCOVERY` is
  required by no stage), rate/target/port/duration-clamped in code,
  and the worker denies it without a recorded administrator approval.
- **Netdiscover / arp-scan** do local layer-2 discovery and run only
  on internal workers holding `LOCAL_LAYER2_ACCESS`; anywhere else the
  executor denies them `UNAVAILABLE_FOR_WORKER`.
- **Workers** are typed (`GENERAL_WEB`, `NETWORK_EXTERNAL`,
  `NETWORK_INTERNAL`, `PACKET_ANALYSIS`) via their own deployment env;
  privileged capabilities cannot be granted by job payloads, and no
  worker receives a Docker socket (§23/§24).

## Normalization, aggregation, findings (§29–§55)

- Services normalize to host/IP, port, transport, state, name,
  product, version, CPE (**only when a tool reported it**), TLS facts,
  **sanitized** banners (control characters/escapes stripped, markup
  neutralized, size-capped — §36) and identification confidence.
- `PortResultAggregator` merges Nmap/Naabu/RustScan/Masscan output into
  ONE canonical service per (host, transport, port), preserving
  provenance: OPEN outranks CLOSED, richer evidence wins field-by-field.
- An open port is **never** a vulnerability. Findings come only from
  the governed check policy (`network-checks.ts`): cleartext-by-design
  services, the unauthenticated-by-design Docker API on 2375, and
  SAFE-script-confirmed conditions (e.g. SMB signing not required).
  Database and remote-admin services are recorded as **exposure
  observations** — the platform never attempts a login, never sprays,
  never guesses SNMP communities (§39–§42).
- Canonical fingerprints include host/port/protocol/service/class so
  network findings correlate through the Prompt 7 engine (e.g. Nmap
  TLS facts + testssl + SSLyze → one canonical finding, §53).
- `VulnerabilityIntelligenceService` is a **prepared boundary only**
  (§55): an empty local dataset, lookups that return nothing rather
  than inventing CVE/CVSS/EPSS/KEV data. Feed ingestion is Prompt 30.

## Packet capture (§43–§48)

`PacketCaptureArtifact` rows hold metadata only; bytes live in object
storage. tcpdump capture is restricted to packet-analysis workers,
explicit interfaces (`any` is refused), bounded duration and packet
count. tshark analyzes stored captures offline. Raw access requires
the OWNER/ADMIN role and is audited (`RAW_PCAP_ACCESSED`) on every
call; the API returns references + integrity hashes, never bytes.

## Budgets, events, audit (§56–§85)

`NetworkBudget` clamps hosts/ports/packets/duration/UDP/capture limits
in code — users can only lower values. Cancellations propagate through
the DAG runner to every running scanner (no orphaned executions).
Scan events are aggregated counts (`network.host_discovered`,
`network.port_discovered`, `network.service_identified`,
`network.targets_expanded`, `network.protected_target_blocked`,
`network.masscan_denied`, `network.local_discovery_unavailable`) —
never per-packet data. Audit actions: `NETWORK_SCAN_REQUESTED`,
`NETWORK_SCOPE_VALIDATED`, `HOST_DISCOVERED`, `PORT_DISCOVERED`,
`SERVICE_IDENTIFIED`, `NETWORK_SCAN_COMPLETED`,
`PROTECTED_TARGET_BLOCKED`, `INTERNAL_SCAN_APPROVED`,
`RAW_PCAP_ACCESSED`.

## Explicitly NOT in this phase (§88)

Metasploit, SearchSploit, Hydra/Medusa, password spraying or brute
force of any kind, Responder, Impacket, AD exploitation, lateral
movement and persistence are not implemented. RESTRICTED catalog tools
stay non-executable. Nothing in this phase executes against a real
target during development or testing — verification is fixture-based
(recorded outputs, RFC 5737 documentation ranges).
