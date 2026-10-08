# iOS Security Analysis (Prompt 35 §45–§49)

iOS static analysis (`IosStaticAnalysisService` — `mobile/ios.ts`)
covers what the artifact format permits, and says so when it does
not:

- **Info.plist** (§45): parsed with the hardened bounded XML/plist
  parser; ATS configuration, URL schemes, privacy usage
  descriptions.
- **Entitlements** (§46): security-relevant entitlements are
  analyzed in context — a legitimate entitlement is not labelled a
  vulnerability without evidence.
- **ATS** (§47): App Transport Security exceptions (arbitrary loads,
  per-domain exceptions, minimum TLS) become observations feeding
  the canonical finding tail.
- **URL schemes** (§48): custom schemes + universal-link metadata
  inventoried, never invoked.
- **Binary metadata** (§45/§49): Mach-O artifacts feed the binary
  security pipeline (Prompt 18 + §51–§65) — format, architecture,
  hardening, symbols — under the same never-execute rule.
- **Signing metadata**: certificate metadata only; no key material
  exists anywhere in the record (§31 discipline).
