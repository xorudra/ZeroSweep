# Mobile Dynamic Analysis (Prompt 35 §71–§99)

Dynamic analysis is the governed exception, never the default
(§16). A session requires ALL of: an explicitly authorized
application/build (§71), a registered lab device whose
`authorizationStatus` is AUTHORIZED (§72–§74 — the V2 API enforces
this before the Prompt 17 instrumentation policy runs), an approved
profile, and reviewed instrumentation modules (§80).

- **Devices** (§72/§73): ANDROID_EMULATOR, ANDROID_TEST_DEVICE,
  IOS_SIMULATOR, IOS_TEST_DEVICE. The platform never connects to or
  instruments arbitrary devices.
- **ADB** (§75–§77): allowlisted operations only (device status,
  install the authorized app, launch/stop the test app, log
  collection with policy, approved transfer of the test artifact).
  There is no generic adb shell (§150 test). §76 prohibitions
  (unrelated app data, credential theft, persistence) are not
  operations in the closed set.
- **Frida** (§78–§82): registry scripts only — id, version, purpose,
  platform, risk class, SHA-256 hash, review status. Unreviewed or
  inline scripts are rejected (§152). Pinning verification (§82)
  observes a test app's control behaviour; it is not a bypass
  service.
- **Objection** (§83/§84): approved defensive workflows only; no
  arbitrary interactive device commands through the UI.
- **Sessions** (§85–§87): runtime evidence carries app version,
  device profile, process, approved module, timestamp, sanitized
  observation. Cleanup is contractual: stop app, remove temporary
  test data, revoke temporary secrets, release device, clear proxy
  configuration.
- **Testing boundaries** (§94–§99): storage/log/clipboard/
  screenshot tests use synthetic data and application-owned storage
  only; biometric/authentication validation is test-case driven and
  never defeats real user authentication; root/jailbreak work
  analyzes implementation evidence — bypassing controls is not the
  objective; business logic reuses human-defined scenarios (§100).
- **Transport honesty**: in this environment no dynamic transport
  is wired — sessions are governed records (see
  `mobile-dynamic-lab.md`). Statuses never claim execution that did
  not happen.
