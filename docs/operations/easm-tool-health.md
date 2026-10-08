# EASM Tool Health

Source health is reported from `EasmAdapterRunResult` rows — real
run outcomes, never synthetic status.

| Status | Meaning | Operator action |
|---|---|---|
| `SUCCEEDED` | Source returned recorded data | None |
| `PARTIAL` | Source returned data with gaps | Review the source note on the run |
| `ERROR` | Transport failed | Check the recorded `errorClass`; do not hammer the source — runs are bounded |
| `NOT_CONFIGURED` | No live transport wired for this source in this environment | Expected in this deployment; supply recorded payloads for verification |
| `SKIPPED_POLICY` | Policy did not select the source, passive-only mode blocked it, or active authorization is absent | Intended behavior — check policy/active grants before changing anything |

Health rules:

- A run is `COMPLETED` only when every selected adapter succeeded;
  otherwise it is `PARTIAL` with per-source coverage on the run row.
- Repeated `ERROR` results for a source across runs = investigate
  the adapter, not the program.
- `NOT_CONFIGURED` is honest state, not an outage: this environment
  deliberately ships without live external source transports, and
  verification uses recorded fixture payloads (example.com /
  RFC 5737 documentation ranges).
