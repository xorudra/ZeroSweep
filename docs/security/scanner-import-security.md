# Scanner Import Security (Prompt 11 §74–§76)

Scanner reports (Nessus `.nessus`, Greenbone XML) are hostile input.

## Preview before commit

Imports are two-phase. **Preview** parses and reports: total findings,
importable findings, duplicates within the report, already-known
findings, per-host scope verdicts (IN_SCOPE / OUT_OF_SCOPE /
UNKNOWN_ASSET) and warnings — before anything is stored. **Commit**
re-submits the report; its SHA-256 checksum must match the preview
record. Out-of-scope findings are counted as quarantined and never
stored; an all-out-of-scope report is REJECTED.

## Parser hardening

- size cap (10 MiB) before parsing;
- DOCTYPE / ENTITY declarations rejected (XXE), external references
  never resolved;
- depth-capped lite XML parser; node/text caps;
- every text field sanitized (control characters stripped) and
  length-capped; plugin output is data, never markup — the web UI
  renders it as text (React-escaped);
- references are kept only when they are http(s) URLs;
- CSV exports escape formula-injection cells (leading `= + - @` get a
  `'` prefix, §83).

## Storage discipline

Raw reports are not stored by the preview/commit API flow (checksum +
summary only). Where raw artifacts are retained (scanner artifact
flows), they carry checksum + version + scan linkage and require
VIEW_RAW_SCANNER_ARTIFACTS — stronger permissions than findings (§16).

Rejected hostile reports are themselves recorded (status REJECTED with
the rejection reason) so import abuse is auditable.
