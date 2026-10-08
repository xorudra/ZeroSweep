# Slack Integration (Prompt 24 §55–§60)

Channel alerts are queued as outbox deliveries — never sent inline —
so a Slack outage cannot block the producing workflow. Alert content
is the sanitized finding view: title, severity, asset reference,
finding link, owner, SLA state (§57). Slash commands and interactive
actions verify Slack's v0 signature with a 5-minute skew window and
are governed by platform RBAC; without a configured signing secret
they are NOT_CONFIGURED (§60). Bot tokens are secret references.
