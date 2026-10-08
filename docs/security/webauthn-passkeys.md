# WebAuthn / Passkey Security (Prompt 23)

- Challenges are hashed, single-use, 5-minute records; registration
  accepts attestation format `none` only, EC2/ES256 keys only, and
  verifies challenge, origin, RP ID hash, user-presence and the COSE
  key structure with a strict minimal CBOR decoder.
- Assertions verify the authenticator signature over
  `authenticatorData ‖ SHA-256(clientDataJSON)`, challenge and origin.
- **Clone detection**: the signature counter must strictly increase
  (when counters are in use); a non-increasing counter fails
  authentication and records an MFA_FAILED event (§34, §121).
- The server stores credential ID + public key + counter only. Private
  keys never leave the authenticator.
- Passkey sign-in yields the phishing-resistant assurance level (AAL3
  class) because the credential is origin-bound (§35 mapping in the
  SDK AAL table).
