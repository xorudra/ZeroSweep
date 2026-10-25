# Mobile Security Engine (Prompt 17)

ZeroSweep's mobile application VAPT engine assesses Android and iOS
applications for applications the workspace **owns or is authorized
to assess**. Static analysis is the default; dynamic analysis is a
separately governed capability that runs only in the controlled
device lab.

## Pipeline

```
register app → upload build (hostile-content intake) → static scan
  MOBILE_ARTIFACT_INTAKE → MOBILE_METADATA_EXTRACTION →
  MOBILE_MANIFEST_ANALYSIS → MOBILE_STATIC_ANALYSIS →
  [MOBILE_BINARY_ANALYSIS] → DEPENDENCY_INVENTORY / SBOM_GENERATION →
  CORRELATION → QUALITY_GATE → REPORTING
dynamic (approved sessions only)
  MOBILE_DYNAMIC_SESSION → [MOBILE_TRAFFIC_ANALYSIS] → CORRELATION
```

Profiles (§12): `MOBILE_STATIC_BASELINE` (default),
`MOBILE_STATIC_COMPREHENSIVE`, `MOBILE_SECRETS_ONLY`,
`MOBILE_BINARY_ANALYSIS`, `MOBILE_DYNAMIC_CONTROLLED`,
`MOBILE_FULL_CONTROLLED`.

## Identity and correlation

- A build is identified by its artifact **SHA-256**; versions are
  display data. A finding's canonical fingerprint includes the
  application, the build hash, the platform, the file/component,
  the rule, the CWE and the finding class (§51).
- Cross-build identity excludes the build hash, so a finding can be
  followed across versions and retested: Build A finding → fix →
  Build B upload → targeted recheck → RESOLVED / REOPENED (§52/§89).
- Static tools observing the same issue (MobSF, JADX, apktool, the
  platform analysis) produce **one canonical finding** with multiple
  observations (§50). A dynamic observation of the same issue marks
  the canonical finding **dynamic-confirmed** and raises confidence;
  both observations are preserved (§88).

## Analysis rules (evidence discipline)

- An exported component is inventoried, not automatically
  vulnerable; a dangerous permission is classified
  (normal/dangerous/signature/custom), not auto-flagged (§20/§21).
- Entitlement or scheme presence is never a vulnerability (§22).
- Certificate findings require real chain/expiry/debug-key evidence;
  certificate pinning is detected as **evidence only** — there is no
  automated pinning or root/jailbreak bypass in any profile (§23/§25).
- Root/jailbreak detection is inventoried; its absence is not
  universally a vulnerability (§26).

## Endpoints and scope

URLs and hosts extracted from an app are `DISCOVERED_REFERENCE`
(§29/§30). They may link to an already-authorized in-scope asset;
they **never** authorize a target and never expand scope.

## Data model

`MobileApplication`, `MobileBuild`, `MobileDeepLink`,
`MobileAppComponent`, `MobileEndpoint`, `MobileNativeLibrary`,
`MobileTestDevice`, `MobileTrafficSession`,
`MobileInstrumentationModule`, `MobileDynamicSession`; findings
carry mobile identity/correlation columns; components and SBOMs hang
off the build (Prompt 12 models, reused).

## Quality gate and budget (§90/§91)

The mobile gate fails on: any Critical finding, any **verified**
secret, any KEV-listed dependency vulnerability, a critical
exported-component issue, or a critical network-security
misconfiguration. Budgets bound artifact size, extracted
files/bytes, decompilation and binary-analysis time, dynamic
duration, traffic capture size, proxy requests and instrumentation
modules. Kill switches reuse the Prompt 16 six-level
`ValidationKillSwitch` — there is no second kill-switch system (§92).

## Prohibited automation (§75/§119)

Credential theft, session-token theft, account takeover, payment
manipulation/abuse, device persistence, spyware behavior, SMS
interception, contact extraction, personal file extraction,
security-control bypass against third-party applications, arbitrary
ADB shell, arbitrary Frida scripts and arbitrary Objection commands
are **never implemented** — requests for them are refused and
audited.
