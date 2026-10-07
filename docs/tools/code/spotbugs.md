# SpotBugs

**Adapter:** `SpotbugsAdapter`, executable `spotbugs`, capability
`CODE_PATTERN_ANALYSIS`. Risk: PASSIVE. Worker: `SOURCE_ANALYSIS`.

Java bytecode/text analysis with the FindSecBugs plugin. Only
SECURITY-category bugs and FindSecBugs pattern types become findings;
style/correctness bugs are counted as skipped non-security issues.
Without compiled classes (and with the no-build policy) the adapter
reports its text-analysis subset or BUILD_REQUIRED — it never
compiles target code.

## Health

UNAVAILABLE when the binary is absent from the worker host.
