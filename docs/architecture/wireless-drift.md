# Wireless Drift (Prompt 19 §55/§56)

## Model

Every AP keeps a configuration history (`WirelessAccessPointHistory`):
a row is appended whenever the posture-relevant state (SSID, channel,
security mode, authentication, approved status) changes. The posture
stage diffs the previous recorded state against the current one.

## Drift kinds

`ENCRYPTION_CHANGED`, `AUTHENTICATION_CHANGED`, `NEW_AP`,
`AP_DISAPPEARED`, `BSSID_CHANGED` (SSID's BSSID set changed) and
`CHANNEL_POLICY_CHANGED` (channel moved outside the approved profile's
channel set). Each drift record carries the structured
`field / fromValue / toValue` triple.

## Semantics

Drift is a **configuration fact, never an accusation**: legitimate change
control produces drift too. Two escalations exist:

- A security-mode **downgrade** (per the mode-strength ordering) also
  raises a `WIRELESS_SECURITY_MODE_DOWNGRADE` finding and a
  `SECURITY_MODE_CHANGED` event.
- Drift feeds Risk Engine V2 as a stored factor (§57); it never, by
  itself, labels anything malicious or an "evil twin".

## Retests (§59)

A wireless retest is a fresh passive observation. A previous finding is
`RESOLVED` only when a fresh observation of the same BSSID no longer
reproduces its fingerprint, `STILL_PRESENT` when it does, and
`INCONCLUSIVE` when the AP was not observed — absence of observation is
never treated as remediation.
