# Incident Management (Prompt 28 operations)

## Declaring & escalating

Declare incidents manually for coordinated work, escalate from an
alert when a single detection needs a team, or escalate an
investigation case when preliminary review confirms impact. All
paths preserve their source links on the incident.

## Working an incident

- Assign a commander; move status only through the legal
  transitions (`DECLARED → TRIAGED → INVESTIGATING → CONTAINED →
  RECOVERING → CLOSED`). The status history is the timeline.
- Narrate on the timeline as you work. Made an error in a note?
  Amend it — never ask for the original to be edited (§46).
- Collect evidence early, with classification set honestly.
  Restricted evidence is visible only to incident members with the
  evidence permission, and every access is logged.
- Use playbooks for the standard shapes (credential compromise,
  exposed secret, malicious indicator match…). Start the run from
  the incident page; complete steps in order with notes.
- Response actions go through propose → approve → execute.
  High-impact actions need a second person (dual) or at least a
  non-proposer (single, SoD). If an execution returns
  NOT_CONFIGURED, the platform capability behind it is unwired —
  record that on the timeline and use the manual path.

## Closing

Recover, then close. Complete the post-incident review: root
cause is CONFIRMED only with evidence in hand (else LIKELY or
UNKNOWN), and file detection-improvement actions — they take
effect only after human approval (§120). Generate the incident
report from the incident page; it is a snapshot of the records,
not a narrative written after the fact.
