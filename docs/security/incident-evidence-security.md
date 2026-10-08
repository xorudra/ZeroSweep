# Incident Evidence Security (Prompt 28 §47–§51, §143/§144)

- **Hash anchoring.** Evidence content is SHA-256 hashed at
  collection; the stored hash is the integrity anchor.
  Verification re-hashes presented content and compares — any
  mutation, however small, fails verification (§143).
- **Telemetry binding.** Evidence sourced from a telemetry event
  must present content whose hash equals the stored event's
  content hash at collection time; a forged "excerpt" is rejected.
- **Access gate (§50).** Reading evidence requires all three: the
  `VIEW_INCIDENT_EVIDENCE` permission, incident membership
  (commander, creator, or evidence manager), and a classification
  within the caller's role ceiling.
- **Access logging.** Every access attempt — allowed and denied —
  is written to `IncidentEvidenceAccess` with actor, action and
  result. A denied attempt is itself evidence (§144).
- **Redaction.** Timeline summaries and communication snapshots
  pass the platform secret scrubber before storage (§157).
- **No admissibility claim.** The platform maintains a custody
  record (collector, time, hash, access/transfer history). It does
  not claim the record is forensically admissible — that judgement
  belongs to the organization's legal process (§51).
