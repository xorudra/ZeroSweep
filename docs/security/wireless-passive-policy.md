# Wireless Passive Policy (Prompt 19 §1/§99)

DSRclone's wireless work is **passive only**. The following are
PROHIBITED AUTOMATION — not implemented anywhere in the codebase, and
not expressible through any API, plan, adapter configuration or lab
workflow:

- Wi-Fi password / WPA key cracking or recovery of any kind
- WPS PIN attacks
- Deauthentication or disassociation attacks (including "handshake
  capture" workflows that induce them)
- Evil-twin or rogue-AP creation
- Credential interception or reuse
- RF jamming
- Wireless persistence mechanisms
- Any attack against nearby third-party networks

## Enforcement layers

1. **Catalog**: active tools (Wifite, hcxdumptool) are DISABLED
   descriptors with no executing adapter; Wireshark is an analyst tool.
2. **Planner**: baseline profiles' allowlists contain only `kismet`,
   `tshark-wireless`, `hcxtools`, `aircrack-ng` (metadata) — plan tests
   assert the forbidden slugs are never selected (§64).
3. **Executor**: wireless adapters run only in the two wireless tool
   stages, only on `WIRELESS_PASSIVE_ANALYSIS` workers, only with
   store-resolved sensor/capture context.
4. **Adapter configuration**: config keys are allowlisted; command,
   filter, shell and credential keys are refused. Aircrack-ng runs with
   the capture reference as its sole argument; cracking-shaped
   configuration is rejected by `AircrackPolicy`.
5. **API**: no endpoint accepts a raw wireless command, arbitrary tool
   arguments or a display filter (§78). Command-shaped lab requests are
   refused and audited (`WIRELESS_ACTIVE_TOOL_BLOCKED`, §93).
