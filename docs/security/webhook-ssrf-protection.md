# Webhook SSRF Protection (Prompt 22 §73/§74)

Webhook delivery is an SSRF surface, so destinations are treated as
hostile until proven safe. `validateWebhookDestination`
(`packages/security-sdk/src/continuous/webhook.ts`) enforces, at
policy-save time and again at every delivery attempt:

1. **HTTPS only.** Plain HTTP destinations are refused.
2. **No credentials in the URL.** `user:pass@host` forms are refused.
3. **Host allowlist.** The destination host must match the policy's
   allowlist exactly or via a `*.suffix` wildcard.
4. **Fresh DNS resolution + protected-destination guard.** The host
   is resolved at validation time and EVERY resolved address is
   checked with the platform's `blockedTargetReason` guard:
   loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16 — cloud
   metadata), RFC1918 private ranges, and `localhost` are refused
   (§115 test cases: 127.0.0.1, 169.254.169.254, localhost all
   blocked).
5. **Internal-infrastructure exception (§74)** exists only when an
   administrator has explicitly approved internal infrastructure for
   the destination AND the host is allowlisted. It is never the
   default and never inferred.

Delivery controls (§73): 5s timeout, max 2 retries, response size
bounded by the provider-neutral delivery policy. Payloads are
signed with HMAC-SHA256; the signing secret is stored only as a
**reference** (`signingSecretRef`) and resolved at send time — the
secret value never touches the database, logs or audit metadata.

DNS is re-resolved at delivery because an allowlisted hostname can
be rebound between save and send; a destination that fails
re-validation records a FAILED delivery with the refusal reason.
