# Cloud Credential Security (Prompt 34 §7/§9/§10)

- Cloud accounts store a credential REFERENCE only (a Secrets
  Management name/path). Plaintext keys, tokens, passwords and
  kubeconfig content are refused at registration (Prompt 14 guards:
  `isValidCredentialReference`, `looksLikeSecretValue` — reused by
  the Prompt 34 §8 authorization evaluation, which refuses a
  secret-shaped reference value).
- Collection uses SHORT-LIVED, TTL-BOUND credentials
  (`CredentialLease`, TTL ≤ 3600s, Prompt 14): assume-role / managed
  identity / workload identity patterns are preferred over static
  keys; leases are never persisted beyond their purpose and never
  appear in logs, exports or AI context.
- The platform identity is READ-ONLY (§5): providers should grant
  the vendor security-audit/read policies; write-capable credentials
  are a misconfiguration the connection test flags via
  PERMISSION_LIMITED / least-privilege review (§13/§14).
- Connection tests (§12) verify tenant identity: the returned
  account/subscription/project MUST match the registered external id
  — a mismatch is an AUTH_FAILED-class failure (ACCOUNT_MISMATCH),
  never a silent re-bind to another tenant.
- Rotation is a Secrets Management operation; rotating a reference
  does not change platform state beyond the reference name.
