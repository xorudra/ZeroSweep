# Wireless Privacy (Prompt 19 §8/§9/§90)

Wireless observation inevitably sees **other people's devices**. The
platform collects the minimum security-relevant metadata and protects
identities by construction:

## Stations

- A station is stored as an **HMAC-SHA256 pseudonym** (`sta-<16 hex>`)
  keyed by the workspace (§9): stable for correlation inside the
  workspace, useless outside it.
- The raw station address never travels in normalized records, findings,
  events or ordinary API views. It may exist only under an elevated
  collection policy, and reads of it are permission-gated
  (`VIEW_RAW_WIRELESS_CAPTURES`) and audited (§30).
- Locally-administered (randomized) addresses are treated as a privacy
  signal, not an identity to defeat.

## Access points

- BSSIDs are masked in ordinary views (`00:0b:86:**:**:**`, §73); the
  full value requires the raw-captures permission.
- SSIDs are sanitized at parse time (§92): ANSI/terminal escapes, control
  and bidi characters stripped, secrets redacted, length bounded. They
  are rendered as inert text everywhere.

## Credentials (§67)

Authentication material can exist inside a capture (hashes, handshakes).
The platform records **only the count** (`authenticationMaterialCount`)
— never the material — and never stores, logs or audits a Wi-Fi
password. The audit metadata contract (§96) forbids credentials outright.
