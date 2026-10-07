# Wireless Lab Policy (Prompt 19 §65/§66)

Active wireless validation is a **governed lab architecture**, not a
feature of baseline assessment. In this build the lab transport is
deliberately unwired: nothing transmits, ever, on the strength of a lab
request.

## Requirements (§65) — all must hold

- An explicit **LAB** environment (never a production/corporate one)
- A dedicated test AP and dedicated test clients
- A recorded authorization for the lab
- A **separate approver** (approval is a distinct duty from requesting)
- Duration within the 1800-second hard timeout
- Kill switch not engaged

When every requirement is met, the honest outcome is
`ELIGIBLE_NOT_PROVISIONED`: the request is recorded and auditable, and
no session is fabricated. When any requirement is unmet the outcome is
`BLOCKED` with the full reason list.

## Synthetic data only (§66)

Even in a provisioned lab, only synthetic/test Wi-Fi credentials may be
used. Real employee, customer or third-party passwords are never stored,
tested or cracked — the policy checks the synthetic marker by presence,
never by value.
