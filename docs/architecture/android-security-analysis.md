# Android Security Analysis (Prompt 35 §20–§44)

Android static analysis runs over the Prompt 17 substrate:
`AndroidManifestAnalysisService`-equivalent platform analysis in the
security SDK (`mobile/manifest.ts`, `mobile/analysis.ts`), fed by
apktool decoding (§25) and JADX decompilation evidence (§27).

- **Manifest** (§20): package, SDK levels, permissions, exported
  components, debuggable, backup, network security config,
  cleartext configuration.
- **Permissions** (§21/§22): classified normal / dangerous /
  signature / special where platform metadata supports it; presence
  alone is not a vulnerability — application context decides.
- **Exported components** (§23): activities, services, receivers,
  providers, intent filters and their permission protection.
- **Deep links** (§24): app links + custom schemes inventoried;
  candidate findings only with security-relevant evidence.
- **apktool** (§25/§26): manifest/resource decoding and
  configuration analysis only. Modified APKs are never rebuilt or
  re-signed automatically.
- **JADX** (§27–§29): class/method metadata and code-search
  evidence. Decompiled code is stored as bounded snippets +
  locations + hashes + references — never whole applications.
- **Crypto / storage / WebView** (§36–§40): weak algorithms, insecure
  modes, hardcoded material and weak randomness only where static
  evidence supports it (library presence alone is not proof, §37);
  unencrypted preferences, backup exposure and logging; WebView
  JavaScript/file-access/mixed-content/bridge exposure.
- **Network config** (§42): cleartext policy, custom trust anchors,
  debug overrides, pinning configuration evidence.
- **Endpoints** (§43/§44): bounded candidate domains/URLs, linked to
  Web/API assets and EASM as DISCOVERED_REFERENCE — extraction never
  authorizes active scanning.
- **Signing** (§41): certificate metadata, signing scheme, expiry,
  debug/test signing indicators. Private keys never exist.
