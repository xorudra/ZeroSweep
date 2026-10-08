# Risk Register (Prompt 26 §42–§59)

One `RiskRegister` per workspace. A `RiskRecord` carries source
(TECHNICAL_FINDING / CONTROL_FAILURE / AUDIT_FINDING / MANUAL /
VENDOR / BUSINESS), likelihood 1–5, and per-dimension impact 1–5
(confidentiality, integrity, availability, financial, operational,
regulatory, reputation).

## Mathematics (SDK, deterministic)

- Inherent score = likelihood × max impact dimension, banded by the
  workspace `RiskMatrix` (configurable within platform bounds:
  `1 <= lowMax < mediumMax < highMax < 25`, multipliers in (0, 1]).
- Residual score = inherent × effectiveness multiplier (EFFECTIVE
  0.4, PARTIALLY_EFFECTIVE 0.7, INEFFECTIVE 1.0 by default), where
  effectiveness is the weakest linked control's latest evaluation.
- **When effectiveness is unknown, residual stays NULL** and the UI
  shows "not assessed" — the platform never invents an exact
  residual (§49).

## Relationship to Risk Engine V3

RiskEngine V3 remains authoritative for technical vulnerability risk
(§54). A register risk created from a finding *links* to it and reads
its band for context; the register never writes a finding's score.

## Treatment & acceptance

Treatment plans (MITIGATE / AVOID / TRANSFER / ACCEPT) hold tracked
actions with owners, due dates, related findings/controls and ticket
references. Acceptance is a workflow: request → decide. Under the SoD
policy the requester **cannot approve their own HIGH/CRITICAL
acceptance** (§57/§130). Acceptances carry an expiry; a sweep returns
expired acceptances' risks to review and records
RISK_ACCEPTANCE_EXPIRED (§59/§131) — nothing stays silently accepted.
Technical (per-finding) exceptions continue to live in the Prompt 20
`RiskException` model and are surfaced read-only next to the register
(§55). Recurring `RiskReview` records capture decisions and next
review dates.
