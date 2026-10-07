# Import Sanitization (Prompt 20 sections 51/97)

Everything arriving from an external platform is untrusted.
Titles, descriptions, URLs and evidence pass through the same
hardened sanitizers used for scanner output (control/bidi
stripping, length caps, scheme allowlist, platform secret
redaction). Imports are bounded: at most 5000 records per job,
bounded nesting depth and payload size - oversized or malformed
payloads are rejected before any row is written. Preview runs the
full sanitize + normalize + fingerprint pipeline without
persisting anything, so what an administrator approves is exactly
what a commit will store.
