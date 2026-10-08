# Attack Surface Intelligence (Prompt 27 §51–§60)

Attack-surface analytics derive from the platform's controlled discovery
inventory (`Asset`, `Service`, `Technology`) — never from live probing by
the analytics layer.

- **Exposure classification** reuses the platform's `deriveExposure`
  (private/loopback/RFC 5737 ranges are not internet-facing).
- **Snapshots** (`ExposureSnapshot`) freeze totals, internet-facing counts,
  unknown-asset counts and shadow-signal counts. Growth is computed
  **between snapshots**; with fewer than two snapshots the API returns
  `null` growth with an honest note — it never invents a baseline (§135).
- **Shadow IT signals** (§55) are heuristics over evidence (e.g. a public
  asset with unspecified criticality). A signal is explicitly *not* a
  verdict of maliciousness or non-compliance.
- **Certificate analytics** (§59/§60): no certificate inventory table
  exists in the platform, so the honest output is the TLS-service count
  plus certificate-class findings — labelled as such in the response.
- Discovered assets **never expand scope**: analytics read inventory; they
  do not create targets or alter scope status.
