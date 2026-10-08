# EASM Discovery Pipeline

One discovery run (`EasmDiscoveryService.runDiscovery`) proceeds in
ordered stages; the authorization gates sit *before* any payload is
ingested, not after.

1. **Program gate** — program must be `ACTIVE` or `DRAFT`; PAUSED /
   ARCHIVED programs refuse runs.
2. **Source selection** — the program's `EasmDiscoveryPolicy` selects
   sources (passive by default). A submitted source the policy did
   not select is recorded `SKIPPED_POLICY` and its payload dropped.
3. **Active gate** — active sources (`DNS_RESOLUTION`,
   `TLS_HANDSHAKE`, `HTTP_PROBE`, `SERVICE_DISCOVERY`) require at
   least one root that is ownership-**VERIFIED** *and* separately
   active-authorized; otherwise they are dropped with result
   `SKIPPED_POLICY / ACTIVE_NOT_AUTHORIZED` and no payload exists in
   the system at all.
4. **Per-item gates** — service observations only for hosts under an
   active-authorized root and only on the approved port set of the
   `EasmServiceDiscoveryProfile`; HTTP observations likewise. Dropped
   items are counted in run coverage (`droppedActive`,
   `droppedUnapprovedPorts`) — visible, never silent.
5. **Wildcard suppression** — candidates under a wildcard zone need
   ≥2 independent sources or DNS corroboration; uncorroborated
   single-source labels are suppressed and counted.
6. **Ingestion** — candidates upsert by
   `(programId, type, normalizedValue)`; every payload item also
   writes an `AssetDiscoveryObservation` (provenance) — merges add
   observations, never duplicate rows.
7. **Intelligence passes** — DNS snapshot/diff + dangling assessment,
   certificate upsert + change events + SAN candidates, technology
   resolution (independent sources only), ownership resolution,
   exposure classification.
8. **Drift** — run snapshot vs latest baseline (or pre-run state):
   flapping filter (first sighting `PENDING_CONFIRMATION`, repeat
   `OPEN`), plus immediate drift for service/DNS/certificate changes.
9. **Disappearance** — untouched candidates gain a miss; at the
   program threshold they become `DISAPPEARED`. Records are never
   hard-deleted by a run.
10. **Completion** — `COMPLETED` only if every adapter succeeded;
    any `ERROR`/`NOT_CONFIGURED` yields `PARTIAL` with per-source
    coverage stored on the run.

## Backpressure

`maxCandidatesPerRun` (default 1000) caps candidate creation per run;
the excess is counted (`suppressedBackpressure`) and the run still
completes honestly. Adapter concurrency is capped in the SDK policy
layer (`EasmResourceGovernor` equivalents are enforced via the run's
single-pass design).
