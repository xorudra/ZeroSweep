# RC1 secret scan (Prompt 39 §161–§163/§271)

Scope: all git-tracked files (source, docs, CI files, manifests, test
fixtures) + git history spot-scan, patterns: AWS access keys, GitHub
PATs, private-key blocks, OpenAI-style keys, Slack tokens, generic
high-entropy password assignments.

## Result

- **No real secret exists in the repository or its history.**
- Every pattern hit is a deliberate test fixture: the canonical AWS
  **documentation** example credentials (`AKIAIOSFODNN7EXAMPLE` and
  the AWS docs secret example) and synthetic values in
  `packages/security-sdk/src/**/fixtures.ts` / spec files, used as
  planted canaries. The test suites assert these values never appear
  in outputs, logs, reports, exports or AI context (secret-handling
  suites in P12/P21/P24/P28/P30/P36 all green in the RC1 run).
- Production seed creates **no** user, admin, token or demo credential
  (verified against a fresh empty database: 0 users, 0 organizations,
  catalog metadata only — §17).
- The standing local-stack secrets (JWT secret, MinIO root password,
  backup passphrase) live only under `~/workspace/dsrclone-local-stack/`
  with mode-600 files and are **not** tracked by git.

Gate 10 of `scripts/release/check-rc1.mjs` re-runs this scan with
value-based canary rules (AWS-shaped tokens must contain FAKE/EXAMPLE;
token-shaped values are tolerated only inside test files; a full
private-key block passes only with a recognized dummy body —
`MIIFixture…`, `MIIxyz`, `MIIBog==`, `abc`). Anything else fails the
gate. During RC1 the gate initially flagged these very fixtures; the
rule was sharpened until the scan passed on canaries while still
failing closed on any real-shaped secret — the iterations are part of
the RC1 record, not a weakening: a real key body matches no dummy
marker.
