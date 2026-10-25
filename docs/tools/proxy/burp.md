# Burp Suite Professional connector

**Product class:** commercial, **ADMIN_PROVIDED** — `BurpConnector`.
ZeroSweep never bundles, downloads or redistributes Burp. The
administrator supplies a licensed Burp environment; ZeroSweep integrates
with what that environment exposes (§9–§12).

## How the integration actually works (honest design)

Burp's live REST API (Enterprise / DAST) does not serve **passive issue
data** to third-party tools, and this connector does not pretend
otherwise. Two real channels are used:

1. **Burp's documented XML issue export** — Burp has exported issues
   (with full request/response evidence) as XML for many versions. The
   `BurpIssueParser` imports exactly that format (XXE-safe reader, size
   and nesting caps §61). Exports can arrive via:
   - **Manual import**: API `POST /scanners/import` with
     `format: "burp-xml"` (Owner/Admin/Security Engineer), or
   - **The bridge** (below) for automated sync.
2. **The ZeroSweep bridge contract** — the administrator runs a small
   bridge **inside their licensed Burp environment** (a Montoya
   extension, or a scheduled export job serving the files) exposing:
   - `GET /dsrclone/health` →
     `{ "data": { "product": "burp", "version": "2025.x", "licenseValid": true } }`
     (license state is read from the response, never assumed)
   - `GET /dsrclone/issues-export` → Burp XML issue export
   - `GET /dsrclone/site-map` →
     `{ "items": [ { "url": "...", "method": "GET", "statusCode": 200 } ] }`

   Register the bridge exactly like any other instance: the
   `endpointReference` name resolves in server configuration
   (`DSRCLONE_SCANNER_ENDPOINTS`); any credential is a reference resolved
   in the worker boundary.

## Priorities (per spec §10)

1. Site-map synchronization → endpoints with provenance (§31)
2. Passive issue import → normalized findings (§32)
3. Request/response evidence references (redacted copies + hashes §26)
4. Issue correlation with ZAP / Caido / Nuclei / Nikto (§33/§36)
5. Active scan — **INTRUSIVE, disabled by default**, full approval gate
   set (§12); this phase prepares the gate and never starts one.

## Not configured?

With no bridge/export configured the connector reports
`NOT_CONFIGURED`/`UNAVAILABLE` honestly — including in the Tools page and
in scan plans — and imports nothing. There is no simulated Burp data in
production paths; fixture XML exists only in the test suite.
