# Incident Playbooks (Prompt 28 §83–§89)

## Declarative steps (§84/§85)

A playbook is an ordered list of steps in nine closed categories:
`INVESTIGATE`, `ENRICH`, `NOTIFY`, `CREATE_TICKET`,
`REQUEST_APPROVAL`, `EXECUTE_APPROVED_RESPONSE`, `WAIT`, `VERIFY`,
`DOCUMENT`. The SDK validator rejects a step carrying any
executable field (`command`, `shell`, `script`, `code`, `sql`,
`eval`, `http`, `url`, `expression`) — a playbook with such a step
is refused wholesale, not sanitized into acceptance (§150). WAIT
steps are bounded (≤ 7 days) and runs are capped at 40 steps.

## Templates (§86)

Seven templates ship with the platform: suspected credential
compromise, critical internet-facing vulnerability, exposed secret,
suspicious privileged login, cloud security incident, DevSecOps
gate incident, and malicious indicator match. Templates are
versioned; a run pins the template version it started with (§87),
so editing a template never rewrites an in-flight run's meaning.

## Runs (§88/§89)

`IncidentPlaybookRun` walks steps strictly in order, recording
completion and analyst notes per step, with `PLAYBOOK_STARTED` /
`PLAYBOOK_COMPLETED` audit events and incident-timeline entries.
A step in the `EXECUTE_APPROVED_RESPONSE` category never executes
anything itself — it points at the response engine, whose approval
policy (including segregation of duties) is the only execution
path. Playbooks coordinate humans and governed actions; they are
not an automation backdoor.
