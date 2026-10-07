# Semgrep

**Adapter:** `SemgrepAdapter`, executable `semgrep`, capabilities
`CODE_PATTERN_ANALYSIS`, `SECURITY_RULE_ANALYSIS`, `DATAFLOW_ANALYSIS`.
Risk: PASSIVE. Worker: `SOURCE_ANALYSIS`, network NO_NETWORK.

Pattern + taint SAST over the snapshot. Rule selection is governed:
packs come only from the approved catalog (`p/security-audit`,
`p/owasp-top-ten`, per-language packs, `p/secrets`), resolved by the
worker from the scan profile and the detected languages (§22).
Repository-supplied rules and arbitrary rule paths are rejected at
configuration validation.

## Output

Semgrep JSON → normalized findings with file/line/column, rule id,
CWE from the rule metadata, redacted snippet, and dataflow steps when
the taint trace is present. Exit code 1 (findings present) is a
successful run.

## Health

UNAVAILABLE when the binary is absent from the worker host.
