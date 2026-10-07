# mitmproxy connector (traffic import)

**Product class:** interactive proxy — `MitmproxyConnector`
(`packages/security-sdk/src/proxy/`), joining the Prompt 8 connector
family (ZAP / Burp / Caido) in this phase (§33).

mitmproxy is import-oriented in DSRclone: an administrator runs it in
their own environment, registers an instance under Settings →
Scanner Instances (endpoint + credential REFERENCE NAMES only, like
every connector), and DSRclone imports its recorded flows:

- HTTP flows become endpoint inventory + `HttpTransaction` records
  (metadata, hashes, redacted display copies — the Phase 8 rules);
- WebSocket handshakes (ws/wss scheme, upgrade headers, or flow
  metadata) become WebSocket inventory, including whether the
  handshake carried authentication material;
- API-looking traffic is classified (REST/GraphQL) with the shared
  `classifyApiKind` logic.

## Honesty rules

- `getIssues()` returns an empty list — mitmproxy has no scanner
  issue feed, and none is invented.
- A reachable instance whose flow export cannot be confirmed reports
  DEGRADED, never HEALTHY (the Caido rule).
- With no instance registered the connector reports NOT_CONFIGURED —
  the honest product state, not an error.
