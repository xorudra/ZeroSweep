# GitHub Integration (Prompt 24 §10–§22)

Preferred auth: GitHub App (§11) — app id + installation id in
configuration, private key as a secret reference. PAT is supported
only when the deployment configures it (§12); both store references,
never values.

- **Webhooks**: `push`, `pull_request`, `check_run` events at
  `POST /api/v1/webhooks/github`, HMAC-SHA256 verified against the
  per-integration webhook secret reference before parsing (§14),
  delivery-id replay protection (§16).
- **Triggers**: push → scan when the repository policy enables it
  (push / default-branch matrix, §31); pull_request → PR assessment
  with diff-aware classification and the policy's gate preset
  (§19/§20).
- **Decoration (§22)**: commit statuses / check runs carry counts and
  a ZeroSweep reference only; publishing requires a live transport —
  without one the result is recorded NOT_CONFIGURED.
- **Repository sync**: installations' repositories imported as
  metadata into staging rows + links (§13).
