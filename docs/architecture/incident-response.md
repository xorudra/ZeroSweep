# Incident Response (Prompt 28 §41–§53, §117–§121)

## Incidents

`SecurityIncident` moves `DECLARED → TRIAGED → INVESTIGATING →
CONTAINED → RECOVERING → CLOSED` (plus `ON_HOLD`); illegal jumps
are rejected. Incidents are created manually, by alert escalation,
or by investigation-case escalation — in every path, links to the
originating alerts/events/cases are preserved as `IncidentLink`
rows, and the incident graph (§73) is a read-only projection of
those links. A failed validation or a contained alert is never
quietly rewritten: incident state changes are timeline entries.

## Timeline (§45/§46)

`IncidentTimelineEntry` is append-only. Corrections are new entries
with `amendsEntryId` pointing at the original — the original text
is never edited, so the record of what was believed when stays
intact.

## Evidence & chain of custody (§47–§51)

`IncidentEvidence` stores collection time, collector, source,
classification, storage reference and a SHA-256 hash of the
collected content. Telemetry-sourced evidence must hash-match the
stored event's content hash at collection time (§143). Every
access — allowed or denied — is written to
`IncidentEvidenceAccess`. Access requires the evidence permission,
incident membership (commander, creator, or evidence manager) and
a classification within the caller's ceiling. The platform records
custody; it makes **no claim of forensic admissibility**.

## Cases, communications, reviews (§52–§53, §92–§94, §118–§121)

`InvestigationCase` is the pre-incident container; escalation
creates the incident, stamps `caseId`, and carries the case's alert
links across. Communications are redacted snapshots with honest
delivery states (in-app recorded; external channels queued via the
notification router, never claimed sent). Incident reports are
deterministic snapshots composed only from incident records.
Post-incident reviews classify root cause as `CONFIRMED`,
`LIKELY`, or `UNKNOWN` — the system never upgrades a guess to a
fact — and detection-improvement actions require human approval
before anything changes (§120).
