# Integration SSRF Protection (Prompt 24 §70, §128, §129)

Every outbound destination — generic webhook subscriptions, SIEM
collectors — passes the Prompt 22 webhook validator before use:

- HTTPS only; no URL credentials; IP literals checked directly.
- Hostnames resolve through the platform resolver and EVERY resolved
  address must be public (`blockedTargetReason`: loopback, private,
  link-local incl. 169.254.169.254, CGNAT, multicast, IPv6 ULA all
  refused).
- **Redirects (§71/§129)**: each redirect hop is re-validated with a
  FRESH DNS lookup (maximum 3 hops). A redirect into a private
  address dead-letters the delivery as SSRF_BLOCKED — the protected
  address is never requested.
- A destination that resolves to protected space at delivery time is
  dead-lettered immediately, without a single HTTP request
  (verified in tests, §128).

Provider API endpoints are configuration, not free-form URLs entered
per request, and ticket/messaging payloads never influence outbound
destinations.
