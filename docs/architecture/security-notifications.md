# Security Notifications (Prompt 22 §65–§75)

`NotificationRouterService` routes events through every enabled
`NotificationPolicy` of the workspace. Channels: IN_APP, EMAIL,
SLACK, TEAMS, WEBHOOK (§66).

## Routing controls

- **Admission** (§67): event-type allowlist, minimum severity /
  priority, risk threshold.
- **Deduplication** (§68): `alertFingerprint` hashes event type +
  finding/asset/CVE identity + content hash. Identical content
  inside the policy's dedup window is SUPPRESSED_DEDUP — a record is
  written, so suppression is visible, not silent (§116).
- **Grouping** (§69): root cause → CVE → schedule → asset → type.
- **Throttling** (§70): sliding one-hour window per policy+channel.
- **Quiet hours** (§72): suppressed as SUPPRESSED_QUIET_HOURS except
  emergency severities (default CRITICAL), which always pass.
- **Escalation** (§71): unresolved P0/P1 notifications older than
  the escalation policy's window are marked escalated.

## Delivery honesty

IN_APP is real delivery: the record IS the inbox item on
/notifications. External providers require an administrator
configuration with credential **references**; none is configured in
this deployment, so EMAIL/SLACK/TEAMS/WEBHOOK records are
RECORDED_NOT_DELIVERED with providerStatus NOT_CONFIGURED. A record
is marked SENT only on provider acceptance — which cannot happen
without a configured provider.

## Webhooks

Destinations are validated at policy-save time AND re-validated at
every delivery attempt (§73): HTTPS only, no URL credentials, host
allowlist (exact or `*.suffix`), DNS resolution re-checked at
delivery, every resolved address passed through the platform
SSRF/protected-destination guard. Signing uses HMAC-SHA256 with a
secret resolved from its stored **reference** — the secret value is
never persisted (see `docs/security/webhook-ssrf-protection.md`).
Delivery policy defaults: 5s timeout, max 2 retries.
