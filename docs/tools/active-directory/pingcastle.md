# PingCastle

**Posture:** DEFENSIVE — posture (healthcheck only) (Prompt 15)

PingCastle runs in healthcheck mode only; any other mode is refused
at plan time. Its XML report is parsed by the XXE-hardened XML
parser; mapped rules are canonicalized onto platform rule ids so
PingCastle and native observations of the same issue converge on one
finding (§61). The PingCastle score is preserved as a separate
metric (result metadata + finding evidence) — it is never folded
into CVSS scoring (§39). Zero-point rules never become findings.
