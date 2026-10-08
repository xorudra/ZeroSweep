# EASM Screenshot Security

Screenshots are restricted evidence: they can capture login pages,
internal hostnames, or third-party branding.

- Screenshot rows store metadata (classification `RESTRICTED` by
  default, retention class, hash when bytes exist) — never embedded
  in candidate payloads.
- Candidate detail responses include screenshot *metadata* only when
  the caller holds `VIEW_EASM_EVIDENCE`; the `storageKey` is never
  serialized without it.
- Raw access goes through `GET /easm/screenshots/:id`, which
  requires `VIEW_EASM_EVIDENCE` (OWNER/ADMIN/SECURITY_ENGINEER and
  analyst leads) and writes a `RAW_EVIDENCE_ACCESSED` audit record
  for **both** ALLOWed and DENIED attempts (§147 test pins the
  denied audit).
- Screenshots are captured only for assets under an active-authorized
  root (same gate as HTTP probing); third-party assets are never
  screenshotted.
- In this environment object storage (MinIO) is not provisioned, so
  screenshot *bytes* are not stored — records honestly carry metadata
  only and no capture claims are made.
