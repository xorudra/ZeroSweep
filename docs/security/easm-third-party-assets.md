# EASM Third-Party & Shared Assets

Discovery inevitably sees assets the organization does not own:
vendors, SaaS, CDNs, shared hosting, lookalikes.

- **Labelling, not accusation.** A lookalike or brand-similar domain
  is an observation with a `BRAND_SIMILARITY` evidence weight of
  0.25 — the lowest ownership signal. The platform never calls an
  asset malicious, phishing, or infringing.
- **Third-party** (`ownershipStatus = THIRD_PARTY`): excluded from
  promotion and from every active probe; still tracked for
  relationship context (e.g. a CNAME dependency) because its outage
  or compromise can matter.
- **Shared** (`SHARED`): infrastructure shared with unrelated
  tenants (shared hosting IPs, SaaS CNAMEs). Signals are computed
  with shared context so a neighbor's service is never attributed to
  the organization; exposure classification notes the sharing.
- **Certificates**: a SAN mentioning a third-party domain creates a
  candidate for visibility, labelled by its evidence; it is never
  promoted on SAN evidence alone (§140 test pins this).
- Human review (`DECLARE_THIRD_PARTY`, `DECLARE_SHARED`) is a normal,
  audited queue action — the unknown-asset queue recommends it when
  evidence points that way.
