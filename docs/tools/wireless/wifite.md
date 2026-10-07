# Wifite — DISABLED (Prompt 19 §21)

Wifite is an automated **active** wireless auditing tool (deauthentication,
handshake capture, WPS attacks, key cracking). It is registered in the
DSRclone catalog as a **DISABLED descriptor only**:

- No executing adapter exists; no plan can select it.
- Baseline profiles are asserted (planner + policy tests, §64) to never
  select it; API requests naming it for a lab validation are refused and
  audited (`WIRELESS_ACTIVE_TOOL_BLOCKED`, §93).
- Its capability (`ACTIVE_WIRELESS_TESTING`) exists in the taxonomy so
  policy can name and deny it — nothing implements it.

Any future lab use would have to arrive through the governed
`WIRELESS_LAB_VALIDATION` architecture (§65) with dedicated test
infrastructure — it is not part of this build.
