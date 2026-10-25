# iOS Security Analysis (Prompt 17)

## Intake

IPA artifacts enter through the same hostile-content intake as APKs
(magic sniffing, SHA-256 identity, hostile archive validation).
Mach-O binaries are analyzed statically only; nothing is installed
or executed.

## Plist / entitlement analysis (§18/§22)

From `Info.plist` and entitlements:

- bundle ID, version/build number, minimum OS version;
- App Transport Security: `NSAllowsArbitraryLoads` and per-domain
  exceptions are evidence for `MOBILE_ATS_ARBITRARY_LOADS`;
- URL schemes inventoried — presence alone is not a vulnerability;
- entitlements (associated domains, app groups, keychain access
  groups, push environment) inventoried as attack-surface facts,
  never as findings by themselves;
- background modes and usage-description strings inventoried.

## Code and secrets

Strings/source artifacts feed the same endpoint extraction and
metadata-only secret detection as Android (type + location + HMAC
fingerprint + redacted preview; raw values never stored).
`MOBILE_HARDCODED_SECRET`, `MOBILE_WEAK_CRYPTOGRAPHY` and
`MOBILE_INSECURE_RANDOM` apply cross-platform.

## Mapping

Findings map to the versioned OWASP Mobile Top 10 (2024) taxonomy
and MASVS v2.1 controls where reliable. ZeroSweep makes **no formal
MASVS certification claims** (§48).
