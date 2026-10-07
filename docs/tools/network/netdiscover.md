# Netdiscover (local ARP discovery)

**Adapter:** `NetdiscoverAdapter`, executable `netdiscover`, stage
`HOST_DISCOVERY` (NETWORK_INTERNAL only). Risk: LOW. Worker:
`NETWORK_INTERNAL` with `LOCAL_LAYER2_ACCESS`.

Discovers live hosts on the local segment via ARP and records them as
host assets with MAC observations.

## Governance (§21/§65)

- Meaningful only from an explicitly approved local/internal worker.
  The executor denies it `UNAVAILABLE_FOR_WORKER` on any worker
  without the layer-2 capability — pinned by end-to-end tests.
- Requires a CIDR target/range (from the approved target/scope, never
  client free text). Produces assets only — never services or
  findings.

## Health

UNAVAILABLE when the binary is absent from the worker host.
