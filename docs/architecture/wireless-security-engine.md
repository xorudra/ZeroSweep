# Wireless Security Engine (Prompt 19)

The wireless engine assesses wireless posture from **passive observation and
offline capture analysis only**. Nothing in ZeroSweep transmits on any wireless
interface: no association, no probing, no deauthentication, no handshake
triggering, no key recovery.

## Pipeline

Profiles (`WIRELESS_PASSIVE_BASELINE`, `WIRELESS_PASSIVE_COMPREHENSIVE`,
`PCAP_ANALYSIS_ONLY`, `WIRELESS_COMPLIANCE`, `WIRELESS_LAB_VALIDATION`) resolve
through the standard DAG planner to:

`AUTHORIZATION_CHECK → SCOPE_VALIDATION → WIRELESS_CAPTURE_INTAKE →
[WIRELESS_PASSIVE_DISCOVERY] → [WIRELESS_PCAP_ANALYSIS] →
WIRELESS_POSTURE_ANALYSIS → NORMALIZATION → CORRELATION → RISK_ANALYSIS →
QUALITY_GATE → REPORT_GENERATION`

- **WIRELESS_CAPTURE_INTAKE** (platform): the scan's `WirelessEnvironment`
  must be registered; otherwise the scan fails honestly as
  `WIRELESS_ENVIRONMENT_NOT_CONFIGURED`.
- **WIRELESS_PASSIVE_DISCOVERY** (tool): Kismet only, on
  `WIRELESS_PASSIVE_ANALYSIS` sensor workers, against an approved sensor.
- **WIRELESS_PCAP_ANALYSIS** (tool): tshark (wireless field set),
  hcxpcapngtool and aircrack-ng metadata — offline, over **approved**
  captures only.
- **WIRELESS_POSTURE_ANALYSIS** (platform): the deterministic SDK posture
  pass (encryption/auth analysis, rogue classification, drift, events,
  quality gate) over the persisted inventory.

## Gates

Scans start only through the gated orchestration path: the environment's
registration target must be VERIFIED and the assessment APPROVED, exactly
like every other ZeroSweep target type. The executor re-checks stage,
worker capability and store-resolved context immediately before running
any wireless adapter. Baseline profiles can never select Wifite or
hcxdumptool — asserted at plan time and at policy time (§64).

## Honest states

Live RF requires dedicated sensor hardware. Without an approved sensor a
discovery stage completes degraded (`WIRELESS_SENSOR_NOT_CONFIGURED`);
without an approved capture the PCAP stage is refused at the executor.
Nothing is simulated: an environment with no observations has no APs, no
findings and no events.
