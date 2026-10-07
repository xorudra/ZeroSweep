# Binary Diffing (Prompt 18 §53–§55)

`POST /binary-diffs` compares two registered artifacts of the same
workspace over their **persisted inventories** and stores a
`BinaryDiff` (summary + regressions + full detail), audited as
`BINARY_DIFF_CREATED`.

Identity rules:

- Functions compare by **name + stable fingerprint** — never by
  absolute address alone (§22): an address move with an unchanged
  fingerprint is not a change.
- Dependencies compare by library, with version changes reported only
  where both versions are evidence-backed (§25).

Regressions are first-class results:

- `HARDENING_REMOVED` — a mitigation went ENABLED → not ENABLED (or
  PARTIAL → DISABLED).
- `VULNERABLE_DEPENDENCY_INTRODUCED` — an added dependency matches a
  `BINARY_DEPENDENCY_VULNERABILITY` finding on the target artifact.
- `FINDING_REAPPEARED` — a fingerprint present on the base artifact's
  resolved set appears again on the target.

The diff never executes either artifact; it is a pure function over
recorded inventories (`diffBinaryArtifacts` in the security SDK).
