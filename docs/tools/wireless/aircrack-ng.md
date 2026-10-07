# Aircrack-ng — metadata only (Prompt 19 §19/§20)

**Role:** offline capture inspection adapter (`aircrack-ng`), restricted
by `AircrackPolicy`.

The adapter invokes `aircrack-ng` with the approved capture reference as
its **sole argument**, which prints the capture's network table
(BSSID/ESSID/encryption evidence). That is the only mode:

- No `-w` wordlist, no key, no PTK/PMK computation — cracking-shaped
  configuration keys are refused by policy before planning.
- No `--deauth`, no replay, no injection modes exist in the adapter.
- Output parsing reads the network table only; ESSIDs are sanitized
  (§92) and security evidence is normalized (§31).

Aircrack's cracking workflows are PROHIBITED AUTOMATION (§99) in
DSRclone — the same standing exclusion as credential attacks elsewhere.
