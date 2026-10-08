# Network Host Discovery (Prompt 33 §19–§25)

Host discovery coordinates Nmap, Netdiscover and arp-scan by network
context. Layer-2 methods (Netdiscover, arp-scan) run only where a
scanner worker is legitimately attached to the authorized local
network — a recorded worker capability, never assumed.

Rules:

- Every observation is a `NetworkHostObservation`: IP, hostname, MAC
  where legitimately observable, vendor hint, discovery method,
  first/last seen, confidence, and a scope status
  (IN_SCOPE / CANDIDATE / EXCLUDED).
- MAC/vendor data is network metadata; it is retained only within
  authorized internal assessments.
- ARP and routing observations NEVER authorize scanning adjacent
  ranges. Observation is not authorization (§21) — out-of-scope hosts
  are recorded as candidates when policy permits and are not scanned.
- Host status (UP/DOWN/UNKNOWN/FILTERED) always carries its evidence.
- Observations merge into canonical assets through the existing Asset
  service — V2 does not keep a parallel host inventory.
