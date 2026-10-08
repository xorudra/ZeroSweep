# Web VAPT Scope Lock (Prompt 32 §133–§141)

## The snapshot

At plan creation the scope is frozen into a `ScanScopeSnapshot`:
sorted origins, hosts and exclusions, plus a SHA-256 hash over the
canonical form. The model has **no `updatedAt`** — snapshots are
immutable by construction. Scope edits create a new snapshot for the
next scan; a running scan's scope never expands (§137).

## Verdicts

Every URL encountered is judged against the snapshot:

- `IN_SCOPE` — origin matches a frozen origin;
- `EXCLUDED` — matches a frozen exclusion (exclusions win);
- `OUT_OF_SCOPE` — anything else, including redirect destinations:
  an out-of-scope redirect is **recorded** (`redirectRecorded`) and
  never followed into active testing (§9/§175).

Newly discovered hosts are `CANDIDATE_ONLY` (§138): they enter the
candidate inventory for ownership verification, not the scan.

## Network-position guards

- **Internal targets (§133):** private/loopback/link-local/CGNAT/ULA
  destinations require explicit internal-scope authorization.
- **Cloud metadata (§134):** metadata destinations (169.254.169.254,
  metadata.google.internal, 100.100.100.200, …) are blocked by
  default; only an approved, isolated metadata test in a controlled
  environment may proceed.
- **DNS rebinding (§135/§194):** resolution results are validated
  against the same guards at connection time by the worker transport
  discipline inherited from the platform SSRF posture — a hostname
  that resolves into a blocked range is refused.
- **Referenced hosts (§139/§140):** hosts inside specifications,
  collections and imported documents are validated like any other
  host — documents confer no trust.
