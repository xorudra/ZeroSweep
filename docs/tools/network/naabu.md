# Naabu (fast port discovery)

**Adapter:** `NaabuAdapter`, executable `naabu`, stage
`PORT_DISCOVERY`. Risk: LOW. Worker: `NETWORK_EXTERNAL`.

Fast SYN/connect port discovery whose results feed Nmap's deeper
fingerprinting. Output is JSONL.

## Governance

- Port lists come from governed port profiles (or validated structured
  custom sets) — never raw strings. Rates are clamped to the network
  budget; target counts to `maxHosts`.
- Naabu reports ports only: its services carry low identification
  confidence (0.5) and no name/product/version — richer evidence from
  Nmap wins in the PortResultAggregator (§49).
- A port Naabu finds open is inventory. Findings require the governed
  check policy over *identified* services (§37) — e.g. port 23 alone
  does not create a telnet finding until service detection confirms it.

## Health

UNAVAILABLE when the binary is absent from the worker host.
