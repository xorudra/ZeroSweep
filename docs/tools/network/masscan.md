# Masscan (high-speed port discovery)

**Adapter:** `MasscanAdapter`, executable `masscan`, no default stage.
Risk: MODERATE (elevated policy). Worker: `NETWORK_EXTERNAL`.

## Governance (§19/§20)

- **Never auto-selected:** Masscan's capability
  (`HIGH_SPEED_PORT_DISCOVERY`) is required by no stage in any
  profile. It runs only when an explicit plan selects it.
- **Administrator approval gate:** the worker executor denies Masscan
  with `MASSCAN_NOT_APPROVED` unless a recorded approval was resolved
  by the store from platform policy state. In this phase no approval
  record source exists, so the honest default state is DENIED.
- **Hard clamps:** rate ≤ 10,000 pps, targets ≤ 4,096, ports ≤ 100,
  duration ≤ 1,800 s (`MASSCAN_HARD_LIMITS`) — requests above them are
  clamped in code; Masscan defaults are never relied on. Scope size is
  computed from effective CIDR host counts and rejected when it
  exceeds the clamped target limit.
- Banner output is sanitized like all scanner text (§36).

## Health

UNAVAILABLE when the binary is absent — and DENIED regardless of
health when no approval is recorded.
