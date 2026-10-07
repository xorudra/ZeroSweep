# hcxdumptool — DISABLED (Prompt 19 §22)

hcxdumptool performs **active** capture (it transmits to elicit
handshakes/PMKIDs). It is registered as a **DISABLED descriptor only**:

- No executing adapter exists; baseline profiles can never select it
  (§64, asserted in tests).
- Its capability (`ACTIVE_WIRELESS_CAPTURE`) exists so policy can name
  and deny it.
- API/lab requests naming it are refused and audited (§93).

Offline processing of captures that already exist is done by
`hcxpcapngtool` (see hcxtools.md) — a different, passive tool.
