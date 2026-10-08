# Mobile Traffic Analysis (Prompt 17 §62–§68)

## Where traffic exists

Only inside the device lab: DSRclone-managed devices on the isolated
test network, during an approved dynamic session. mitmproxy is the
lab proxy; Burp Suite is reused through the Prompt 8 connector with
the `MOBILE_PROXY_ANALYSIS` capability — there is no unrestricted
Burp control (§65).

## What is captured

Flow **metadata**: hosts, paths (sanitized), methods, status codes,
sizes, timing. Observed hosts join the endpoint inventory as
`DISCOVERED_REFERENCE` — observation never authorizes a target
(§64). Cleartext traffic observed at runtime raises the runtime
finding `MOBILE_RUNTIME_CLEARTEXT_TRAFFIC`, which confirms the
static configuration finding and increases its confidence (§88).

## Sanitization (§68)

Traffic is sanitized by default: authorization headers, cookies and
sensitive bodies are redacted at capture; the traffic UI shows
metadata only — no sensitive bodies. Access requires
`VIEW_MOBILE_TRAFFIC` and is audited (`MOBILE_TRAFFIC_ACCESSED`).

## TLS interception (§66/§67)

Interception is permitted only in the lab, with a **temporary** CA
installed on the lab device for the session and removed afterwards.
The DSRclone CA is never installed on personal devices. Capture size
and request counts are budget-bound (§91).

## Prompt 35 V2 (§88–§93)

- Capture sessions are created via
  `POST /api/v1/mobile/artifacts/:id/traffic-sessions` and recorded
  as REQUESTED with an explicit scope statement: traffic generated
  by the authorized test application on the authorized device
  within the session only (§90). Out-of-scope records fail the SDK
  scope evaluation (`evaluateTrafficScope`) and are never stored.
- Redaction (§91) is implemented in `mobbin/traffic.ts`:
  Authorization/Cookie/API-key headers are replaced wholesale,
  sensitive body fields are redacted by name, and Bearer-scheme
  credentials are redacted wherever they appear — before
  persistence, logs, reports or AI context (§154 test).
- TLS observations (§93) — cleartext, certificate-validation
  failure, deprecated TLS version — are recorded as observations
  and reach findings only through canonical normalization.
- Observed endpoints correlate to the API inventory as
  DISCOVERED_REFERENCE (§92): linked for review, never
  auto-scanned.
