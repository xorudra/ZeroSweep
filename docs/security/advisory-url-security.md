# Advisory URL Security (Prompt 30 §128)

Advisory and CVE references are URLs supplied by third-party feeds — they are stored and rendered as links in analyst surfaces, so they are validated at ingestion (`validateReferenceUrl`):

- Scheme allowlist: `http:`/`https:` only. `javascript:`, `data:`, `file:` and scheme-relative URLs are dropped (the reference itself is dropped, the advisory is kept).
- No embedded credentials (`user:pass@host`) — credential-bearing URLs are rejected outright.
- Length cap 2048 characters.
- References render as label + URL text from the validated record only; the web tier never fetches reference URLs server-side, so a hostile advisory cannot turn the platform into an SSRF client. (The recorded malicious-fixture test includes a link-local cloud-metadata URL: it is dropped at parse time.)
