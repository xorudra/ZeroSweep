# Inbound Webhook Verification (Prompt 24 §14–§17, §111–§116)

Inbound webhooks are hostile input. The pipeline is fixed:

1. **Size cap**: raw body capped (1MB SDK verify; 2MB HTTP
   collection). Oversize → reject before any trust.
2. **Signature first**: GitHub HMAC-SHA256, Bitbucket HMAC, GitLab
   shared-token compare, Slack v0 signing with a 300-second skew
   window — all timing-safe comparisons, verified BEFORE the payload
   is parsed into trusted structures. A failure returns 401 and is
   recorded as a REJECTED event.
3. **Replay protection**: provider delivery ids are unique per
   integration (`InboundIntegrationEvent`); a duplicate is recorded
   `IGNORED_DUPLICATE` and never processed twice (§16/§113-telemetry).
4. **Allowlist**: the repository must be linked (the link table is
   the allowlist) AND belong to the workspace whose integration
   verified the signature — cross-tenant delivery ids are refused
   (§133).
5. **Governed triggers only**: a verified webhook may start a scan of
   the linked VERIFIED target when an APPROVED assessment already
   exists and fresh-DNS scope revalidation passes. It can never
   approve an assessment, verify a target, widen scope, or create a
   target (§136).

Payload fields stored are sanitized (see
`docs/security/devsecops-data-redaction.md`); the raw payload is
never persisted.
