# EASM DNS Intelligence

- **Snapshots**: every run stores a `DnsSnapshot` per domain with a
  SHA-256 content hash over the canonical record set. History is
  append-only — public DNS cannot be re-queried for the past, so the
  snapshots *are* the history.
- **Diffs**: `diffDnsSnapshots` emits typed change events (record
  added/removed, target changed, nameserver changed, MX changed,
  CAA/CNAME/TXT changed). Changes on a candidate produce
  `DNS_CHANGED` drift and `EASM_DNS_CHANGED` audit entries.
- **Wildcard detection**: three distinct probe labels resolving to
  the same address set ⇒ wildcard zone. Children of a wildcard zone
  need independent corroboration before they are believed (§132).
- **Dangling DNS**: a CNAME to a known claimable service suffix whose
  target does not resolve (`NXDOMAIN`/`SERVFAIL`) creates a
  `DanglingDnsCandidate` — **a candidate with evidence**
  (`evidence` records target, service, resolution). The platform
  never claims a takeover is possible; subdomain takeover *probing*
  is an offensive capability and is policy-excluded. Candidates that
  resolve produce findings of type informational only.
- **Resolution states** are recorded per snapshot (`RESOLVES`,
  `NXDOMAIN`, `SERVFAIL`, `TIMEOUT`, …) from recorded evidence; no
  live resolver runs in tests or in this environment.
