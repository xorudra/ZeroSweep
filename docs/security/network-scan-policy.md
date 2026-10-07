# Network Scan Policy (Prompt 10)

The rules below are enforced in code — in the security-sdk policy
modules, the worker's executor gates and the parsers — and pinned by
tests. They are not configuration suggestions.

## Target and scope rules

1. A network scan runs only against a **VERIFIED** target with an
   **APPROVED** assessment and an explicit scope (the platform-wide
   gates, re-evaluated in the worker immediately before execution).
2. CIDR size is policy: single host and small ranges are normal; large
   ranges need elevated approval; very large ranges need an
   administrator; ranges above the hard ceiling are denied
   (`CidrPolicyService`, thresholds configurable by administrators).
3. **Protected destinations are always denied** — loopback,
   link-local/cloud-metadata, unspecified ranges, and the platform's
   own infrastructure networks (database, Redis, object storage,
   Docker/Kubernetes control planes) when configured. No approval,
   including an internal engagement, overrides this.
4. Private ranges (RFC 1918, CGNAT, IPv6 ULA) require an **approved
   internal engagement** (`NETWORK_INTERNAL` profile, internal worker,
   explicit scope, authorized role, approval record — §64).
5. Hostnames are re-resolved immediately before execution; **every**
   resolved address must pass scope + protected-destination checks.
6. Discovered assets never expand scope. Out-of-scope discoveries are
   recorded with their verdict and never handed to downstream tools.

## Tool rules

7. Tool configuration is typed data only. There is no endpoint, field
   or plan that carries a raw command, argument string or shell
   fragment; plans are argument arrays executed without a shell, and
   target tokens carrying shell metacharacters or leading dashes are
   rejected before plan construction (§82).
8. **NSE governance (§14):** every Nmap script is classified SAFE /
   REVIEW_REQUIRED / INTRUSIVE / DISABLED in a curated, versioned
   catalog. Automated profiles select SAFE scripts plus
   administrator-approved REVIEW_REQUIRED ones. INTRUSIVE and DISABLED
   scripts (vuln probes, brute force, exploitation, DoS) can never be
   selected — an approval list naming them is stripped in code. Broad
   category expressions (`default`, `vuln`, `brute`, `all`) are never
   emitted. Unknown scripts default to REVIEW_REQUIRED.
9. **Port profiles (§27):** named, administrator-managed sets only.
   `FULL_TCP` is never a default and is never derived from a profile.
   Custom sets are validated structured input (integers, range-checked,
   count-capped) — never CLI text. Broad UDP scanning is off by
   default; a small approved UDP set exists (§28).
10. **Masscan (§19/§20):** never auto-selected (its capability is
    required by no default stage), requires an explicit profile +
    recorded administrator approval (executor gate
    `MASSCAN_NOT_APPROVED`), and runs under hard platform clamps for
    rate, targets, ports and duration — Masscan's own defaults are
    never relied on.
11. **Local discovery (§21/§22/§65):** Netdiscover and arp-scan run
    only on internal workers holding `LOCAL_LAYER2_ACCESS`; on any
    other worker the executor denies them `UNAVAILABLE_FOR_WORKER`.
12. **Credential attacks do not exist here (§88):** no brute force, no
    password spraying, no community-string guessing, no login attempts
    against discovered services. Authenticated checks, where a later
    phase adds them, take credentials by secret reference only.

## Evidence rules

13. An open port is inventory, not a vulnerability (§32). A finding
    requires a governed check whose output confirms the condition
    (§37); CVE/CVSS data comes only from source output or the curated
    taxonomy — never invented (§55 prepared-only intel boundary).
14. Scanner output is hostile input: XML is parsed without DTDs or
    external entities under size/depth caps; banners are sanitized
    (escapes/control characters stripped, markup neutralized,
    size-capped) before storage or display (§16/§36/§75).
15. Raw tool output and packet captures live in object storage with
    retention; raw PCAP access is role-gated and audited on every
    access (§47/§74).

## Rate, budget and cancellation rules (§56–§63)

16. Every network run is budget-clamped (hosts, ports per host, total
    ports, packets/second, duration, UDP ports, capture duration/size,
    parallelism). Users may only lower values.
17. Cancellation terminates all running scanners for the scan — no
    orphaned executions; interrupted scans checkpoint by target chunk
    and can resume without restarting completed chunks.
