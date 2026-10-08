# Report Access Control (Prompt 37 §82/§85/§105/§106)

- **Internal access** follows the §127 permissions: MANAGE_REPORTS
  authors, REVIEW_REPORTS reviews, APPROVE_REPORTS approves,
  FINALIZE_REPORTS finalizes and shares. When a report requires a
  separate approver, its author cannot approve it (§85 SoD).
- **Document control** (§82): every report and version carries
  author/reviewer/approver identity, classification, version and
  timestamps; finalized versions are immutable.
- **Client access** (§105): clients can list and download only
  FINALIZED reports scoped to their organization or engagement,
  rendered from the frozen ReportVersion document.
- **Share links** (§106): created only for FINALIZED reports. The
  raw token (32 random bytes) is returned exactly once; only its
  SHA-256 is stored. Links carry an expiry (default 72h), an
  optional download limit, and are revocable. Expired, revoked,
  exhausted and unknown tokens are indistinguishable 404s. Every
  resolution increments the counter and writes an audit event.
- **Private by default** (§107): a report with no share link and no
  client scoping is reachable only by workspace staff with the
  report permissions.
