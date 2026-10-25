# RustScan (fast port discovery)

**Adapter:** `RustScanAdapter`, executable `rustscan`, stage
`PORT_DISCOVERY`. Risk: LOW. Worker: `NETWORK_EXTERNAL`.

Fast port discovery with controlled batch/timeout settings; output is
parsed from RustScan's greppable format by ZeroSweep itself.

## Governance

- **No downstream-command passthrough (§18):** RustScan can hand
  results to another program via a `--` separator and trailing flags.
  This adapter NEVER emits that separator or any `-sV`/`-A`-style
  passthrough — pinned by tests. Ports are normalized by the platform,
  and service detection is Nmap's governed job.
- Targets, ports and rates follow the same profile/budget rules as
  Naabu. `FULL_TCP` maps to the governed range expression only when
  the profile was explicitly selected.

## Health

UNAVAILABLE when the binary is absent from the worker host.
