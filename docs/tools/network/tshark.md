# tshark (offline capture analysis)

**Adapter:** `TsharkAnalysisAdapter`, executable `tshark`, capability
`PACKET_ANALYSIS`. Risk: PASSIVE. Worker: `PACKET_ANALYSIS`.

Analyzes **stored, authorized** packet captures offline: protocol
hierarchy metrics and HTTP transaction inventory (method, host, path,
status) merged into the platform's transaction model.

## Governance (§45/§46)

- Offline-first: the input is an object-storage capture **reference**
  (`scans/…` keys only — filesystem paths and URLs are rejected at
  config validation), resolved inside the worker boundary.
- Wireshark itself is a manual analyst/desktop tool: it has no
  adapter and never executes on a worker; its authorized exports are
  imported as captures and analyzed here.

## Health

UNAVAILABLE when the binary is absent from the worker host.
