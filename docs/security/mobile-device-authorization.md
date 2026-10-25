# Mobile Device Authorization (Prompt 35 §72–§76/§151)

A dynamic session may only ever touch a device that is:

1. registered in the SAME workspace (`MobileTestDevice`),
2. of a supported type (ANDROID_EMULATOR, ANDROID_TEST_DEVICE,
   IOS_SIMULATOR, IOS_TEST_DEVICE),
3. ZeroSweep-managed or organization-owned, and
4. marked `authorizationStatus = AUTHORIZED`.

Registration is not authorization. The Prompt 35 API checks the
authorization status BEFORE the Prompt 17 instrumentation policy:
an unapproved device produces a BLOCKED session record + a
`MOBILE_DYNAMIC_ACTION_BLOCKED` audit entry + a 400 — the §151
device-ownership test. Personal devices are never targeted (§76);
no unnecessary personal device identifiers are stored.
