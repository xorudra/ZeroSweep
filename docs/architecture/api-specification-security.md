# API Specification Security (Prompt 32 §35–§47)

Specifications and collections are **untrusted input**:

- Embedded scripts in Postman/Insomnia collections are **never
  executed** (§141).
- Hosts referenced by the document are validated against the importing
  service's scope (§139/§140) — accepted hosts recorded, rejected hosts
  recorded and never fetched.
- The raw document is not retained in Postgres: checksum + object
  storage reference only (the Prompt 9 import posture), and the V2
  import freezes an immutable `ApiSpecificationSnapshot` (§36).
- Test data comes from approved test-data profiles — production data
  is never used as test input (§38).
- Sensitive values inside a specification (example tokens, keys) are
  **redacted before persistence** in derived records (§39).

## Operations

Operations inherit the Prompt 9 `ApiOperationPolicyEngine` verdicts:
state-changing methods need explicit profile enablement (§46),
destructive operations stay blocked, and every operation test runs
inside the plan's request budget (§48).

## Schema-conformance testing

Schemathesis runs only its SAFE check classes (the Prompt 9 selector);
failures are conformance findings with the operation as evidence.
Passing checks produce no findings.
