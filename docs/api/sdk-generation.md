# SDK Generation Architecture (Prompt 40 §161)

- The API publishes an OpenAPI document; client SDKs are GENERATED
  from it (never hand-maintained forks), one per major API version.
- Generation inputs: OpenAPI schema + the shared error model
  (structured errors incl. `QUOTA_EXCEEDED`, §51).
- Generated clients must not embed credentials; authentication is
  injected by the caller (§160).
- A large custom CLI is explicitly out of scope (§162): automation
  uses the API/SDKs; the product remains GUI-first.
