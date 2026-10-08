# Attack-Surface Monitoring (Prompt 22 §34–§36)

The monitored attack surface is the set of assets captured in
immutable `AssetSnapshot` rows. Each capture normalizes every asset
to `{assetKey, host, type, exposure, scopeStatus, criticality,
ports, services, endpointCount, stateHash}` where `assetKey` is
`targetId|type|host`.

Exposure is **evidence-based**: a stored public IP means
INTERNET_FACING; a stored private/loopback/link-local IP means
PRIVATE; anything else is UNKNOWN. Exposure is never guessed from a
hostname alone (§36).

Comparison of consecutive captures produces `AttackSurfaceChange`
records (see `security-drift.md`). Monitoring posture:

- Discovered assets appear as changes with detail text stating they
  are DISCOVERED and **not authorized for intrusive testing** (§35).
  Turning a discovery into a target remains the normal human flow:
  create target → verify ownership → approve assessment → only then
  can a schedule reference it.
- A private asset becoming internet-facing raises a HIGH priority
  change plus a NEW_PUBLIC_RESOURCE record (§36/§108).
- Monitoring never scans on its own: surface data comes from
  snapshot captures of stored inventory (which scans and imports
  maintain), not from scheduler-initiated probing.
