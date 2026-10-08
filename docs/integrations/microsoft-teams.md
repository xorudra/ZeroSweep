# Microsoft Teams Integration (Prompt 24 §55–§60)

Teams notifications use connector webhooks / MessageCards built from
the same sanitized finding view as Slack, queued through the outbox
with identical retry/dead-letter semantics. Destination URLs are
SSRF-validated before first use and are treated as credentials:
stored as configuration references, never echoed in API output
beyond `secretConfigured`-style flags.
