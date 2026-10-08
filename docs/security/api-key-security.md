# API Key Security (Prompt 23)

- 32-byte random secrets, `dsr_live_` prefix for leak-scanner
  detectability, SHA-256 hash at rest, plaintext shown exactly once.
- Verification is constant-time against the stored hash (SDK
  `verifyTokenHash`); revoked and expired keys are denied with reasons
  recorded, and disabled service accounts deny their keys (§135).
- The scope catalog is closed and typed — privilege cannot be smuggled
  through free-form scope strings (§79, §133).
- Organization policy can disable personal access tokens and cap
  lifetimes (§84); rotation uses an overlap-then-revoke sequence (§81).
- Logs and audit metadata contain prefixes only (§83).
