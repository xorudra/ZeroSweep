# EASM Certificate Intelligence

- Certificates upsert by normalized SHA-256 fingerprint; every
  observation of a certificate (host, source, timestamp) is an
  `EasmCertificateObservation`.
- **States** are computed from stored records, never cached claims:
  `HEALTHY` (>30d), `EXPIRING` (≤30d), `URGENT` (≤7d), `EXPIRED`.
  Renewal recommendations are threshold-derived text on the
  certificates endpoint (renew < 30d, urgent < 7d, replace expired) —
  no external CA calls are made.
- **Change events**: `diffCertificate` distinguishes RENEWED (same
  SAN set, later expiry), SAN_ADDED / SAN_REMOVED, ISSUER_CHANGED,
  EXPIRY_APPROACHING, CERTIFICATE_EXPIRED — emitted as drift.
- **SAN discipline (§41/§140)**: a SAN in a certificate creates an
  asset *candidate* with `CERTIFICATE_SAN` evidence (weight 0.35). It
  never confirms ownership alone and never authorizes anything. The
  test suite pins this: SAN-only candidates stay
  `activeTestingStatus = NOT_AUTHORIZED` and `ownershipStatus !=
  VERIFIED`.
- Weak-signature and self-signed observations are recorded as
  certificate facts when present in the recorded evidence; the
  platform does not fetch live chains in this environment.
