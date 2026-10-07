# Runtime Security (Prompt 13 §57–§63)

Runtime detections (Falco-class sensors) use a **separate ingestion
path** — they are not scan results and never pass through scan workers.
The sensor runs outside DSRclone (DSRclone never deploys it); events
arrive as JSON lines through the trusted ingestion endpoint or the
Falco connector.

## Pipeline (§59/§60)

Every event is validated, then **sanitized before storage**: terminal
escape sequences, C0/C1 control characters, bidi overrides and embedded
newlines in single-line fields are stripped, secret-shaped substrings
are redacted, and lengths are capped. Event fields are hostile input —
a crafted command line in an event must not become stored XSS or a
forged log line downstream. Sanitized events persist as
`RuntimeSecurityEvent` rows and are audited (`RUNTIME_EVENT_INGESTED`).

## Semantics (§61–§63)

- A runtime event is a **detection, not a vulnerability**. It never
  enters the findings pipeline.
- Correlation with workload posture (privileged, publicly exposed,
  may-run-as-root) raises triage context only; correlation with a KEV
  CVE raises a contextual signal. Neither ever claims exploitation
  occurred.
- Ordinary users cannot upload arbitrary Falco rules (§61): ingestion
  payloads name an existing sensor rule; rule definition is a reviewed,
  administrative deployment concern outside this path.
