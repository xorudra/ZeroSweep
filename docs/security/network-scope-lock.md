# Network Scope Lock (Prompt 33 §11/§12/§21)

The scope lock is the platform's central network-safety invariant:

- At plan/run start an immutable snapshot is frozen — hosts, CIDRs,
  exclusions and a SHA-256 hash — into the canonical
  `ScanScopeSnapshot`. It has no update path; plans link to it.
- A running scan cannot expand beyond the snapshot. There is no API,
  worker flag or AI action that widens it.
- Hosts discovered outside the snapshot (via ARP, DNS, routing,
  certificates or a scanner's own expansion) are recorded as
  CANDIDATES when policy permits. They are never scanned, never
  probed, and never promoted automatically — promotion requires the
  full target governance chain (verified target + approved
  assessment) like any other scope.
- Excluded entries win over inclusions.
- Private/internal ranges require an approved internal engagement;
  loopback, link-local/metadata and platform networks are always
  denied — no engagement covers them (Prompt 10 destination policy,
  unchanged).
