# Controlled Callback Service (Prompt 16 §47–§50)

Some safe validations need a callback (canary) destination owned by the
assessment environment — for example confirming that an SSRF-class
finding reaches only an explicitly controlled endpoint. Validation
must **never** target cloud metadata services, internal
administration systems, or localhost services; controlled callbacks
exist so the only reachable "internal-looking" destination is one
DSRclone itself operates for the assessment.

## Token discipline

- Tokens are 32 random bytes (base64url), issued per workspace with a
  short expiry (default 10 minutes, hard bounds 60s–1h).
- Only the **SHA-256 hash** of a token is stored. The raw token is
  shown exactly once, at issuance.
- Tokens are **tenant-bound and session-bound**: verification checks
  workspace and session in constant time.
- A token is **not authorization**. It correlates a callback to a
  validation session; it grants nothing, and possessing one does not
  let anyone start, approve, or widen a validation.
- Tokens are single-use: first ingestion consumes them; replays are
  rejected (`ALREADY_CONSUMED`), as are expired (`EXPIRED`) and
  mismatched (`TENANT_MISMATCH`, `SESSION_MISMATCH`) tokens.

## Ingestion

`POST /api/v1/validations/callbacks/:token` is public by necessity (the
callback arrives from the target side) but returns an **opaque
acknowledgement only** — no tenant metadata, no session details, no
workspace identifiers. Ingestion is rate-limited per token and per
source IP. Stored events keep **minimal metadata**: kind (HTTP/DNS),
source IP, timestamp.

## DNS callbacks

DNS callbacks use validation domains owned and operated by DSRclone
only; the token is the leftmost label and the same verification core
applies. Third-party callback/interaction domains are never used.

## Enablement

Callbacks are disabled per workspace until an administrator enables
them in the validation policy (§77). Issuing a token requires
`RUN_SAFE_VALIDATION`.
