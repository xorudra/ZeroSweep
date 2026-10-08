# Attack-Path Analysis (Prompt 27 §84–§87, §107)

Attack-path **candidates** are prioritization aids for analysts: chains of
the form `INTERNET → asset → finding → sensitive downstream asset` built
from graph edges that all carry evidence.

- Candidates are generated only for internet-facing assets with open
  CRITICAL/HIGH findings and a sensitive (CONFIDENTIAL/RESTRICTED data or
  critical) same-network downstream.
- Scoring is a documented deterministic formula in the SDK
  (`scoreAttackPath`, 0–100: exposure, severity, verification, intel,
  downstream sensitivity). It is a ranking heuristic, not a probability.
- Candidates are upserted by fingerprint; when their evidence disappears
  they transition to `REMOVED` (§87).
- Access is audited (`ATTACK_PATH_ACCESSED`) and restricted to staff roles
  (`VIEW_ATTACK_PATHS`).
- The AI explanation endpoint states plainly that a candidate is **not an
  exploitation procedure** (§107); the platform never emits exploitation
  steps.
