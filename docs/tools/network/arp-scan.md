# arp-scan (local ARP discovery)

**Adapter:** `ArpScanAdapter`, executable `arp-scan`, stage
`HOST_DISCOVERY` (NETWORK_INTERNAL only). Risk: LOW. Worker:
`NETWORK_INTERNAL` with `LOCAL_LAYER2_ACCESS`.

ARP-based local discovery; output parsed from arp-scan XML (through
the same hardened XML reader as Nmap) or its text table.

## Governance (§22/§24/§65)

- Internal workers only, approved local network, explicit interface
  when configured. Broad host privileges are never granted to general
  workers: without `LOCAL_LAYER2_ACCESS` the executor denies the run
  before any plan is built.
- Produces host assets + MAC observations only.

## Health

UNAVAILABLE when the binary is absent from the worker host.
