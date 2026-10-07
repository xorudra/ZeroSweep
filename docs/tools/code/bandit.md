# Bandit

**Adapter:** `BanditAdapter`, executable `bandit`, capability
`PYTHON_SECURITY_ANALYSIS`. Risk: PASSIVE. Worker: `SOURCE_ANALYSIS`.

Python AST security checks (subprocess use, hardcoded passwords,
weak crypto, unsafe deserialization, …). JSON output; exit code 1
(findings present) is success. Hardcoded-password checks (B105/B106/
B107) produce **secret findings** — the literal is fingerprinted at
parse time and never stored (§40).

## Health

UNAVAILABLE when the binary is absent from the worker host.
