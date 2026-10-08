# Web VAPT Secret Redaction (Prompt 32 §50–§53, §114, §178)

## Rules

1. Credentials exist in the platform **only as secret references**.
   Plans, targets, sessions, matrices and scenarios store reference
   IDs — there is no field anywhere in the V2 schema that can hold a
   credential value.
2. Session records store presence flags and fingerprints
   (`WebScanSession.redactedSummary`), never cookie/token values.
3. Evidence is redacted **before** persistence: authorization
   headers, cookies, bearer/basic credentials and secret-shaped
   fields pass the platform redactor (`redactEvidenceText`).
4. Audit metadata for V2 actions contains identifiers and counts
   only; `AUTH_PROFILE_USED` records the profile ID and plan ID.
5. AI suggestions are grounded on counts and statuses — never on
   session material — and the copilot has no execution surface.

## The planted-credential test (§178)

The SDK fixture set plants a synthetic token
(`FIXTURE-TOKEN-…`) inside the recorded SQLmap output. The test suite
asserts the token appears in **no** parsed finding, evidence string or
serialized parse result. Any future parser change that breaks this
assertion fails the build.
