# Control Library (Prompt 26 §7–§18)

A `SecurityControl` is DSRclone's internal normalized control. The
shipped library (SDK `CONTROL_LIBRARY`) holds ~30 controls, each with:

- `code` (stable, e.g. `MFA-ENFORCEMENT`), title, description
- `controlType`: PREVENTIVE / DETECTIVE / CORRECTIVE / GOVERNANCE
- `implementationType`: TECHNICAL / ADMINISTRATIVE / PHYSICAL / HYBRID
- one `ControlTest` definition: method (AUTOMATED / MANUAL / HYBRID),
  automation level (FULL / PARTIAL / NONE), frequency, expected
  result, evidence requirements, and — for technical controls — the
  signal keys it is evaluated from.

The platform **distinguishes what it can technically validate from
what requires human evidence**: administrative controls (incident
response plan, policy governance, risk process, vendor management,
training) have MANUAL tests with automation level NONE and no
signals. They can only be supported by reviewed manual evidence; no
technical signal can mark them FULL (§18).

Implementation status (§14: NOT_IMPLEMENTED → IMPLEMENTED) is tracked
separately from test outcome. Effectiveness (§15: NOT_TESTED /
EFFECTIVE / PARTIALLY_EFFECTIVE / INEFFECTIVE / INCONCLUSIVE) is set
by the latest evaluation only.

Ownership (§13) is a `ControlOwner` row: USER, TEAM or BUSINESS_UNIT.
Workspaces may add their own controls (MANAGE_CONTROLS); catalog
controls seed idempotently on first use per workspace.
