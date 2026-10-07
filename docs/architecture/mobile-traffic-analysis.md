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
