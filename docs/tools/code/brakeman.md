# Brakeman

**Adapter:** `BrakemanAdapter`, executable `brakeman`, capability
`FRAMEWORK_SECURITY_ANALYSIS`. Risk: PASSIVE. Worker:
`SOURCE_ANALYSIS`.

Ruby on Rails framework security analysis (SQL injection, XSS,
command injection, unsafe redirects, mass assignment). Runs only when
the snapshot detection found a Rails application. JSON warnings map
to findings with the check's CWE id when Brakeman provides one.

## Health

UNAVAILABLE when the binary is absent from the worker host.
