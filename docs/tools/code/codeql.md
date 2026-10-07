# CodeQL

**Adapter:** `CodeqlAdapter`, executable `codeql`, capabilities
`SECURITY_QUERY_ANALYSIS`, `DATAFLOW_ANALYSIS`. Risk: PASSIVE.
Worker: `SOURCE_ANALYSIS`, network NO_NETWORK.

Deep dataflow SAST. Query suites are governed (`security-extended`);
custom query packs are never accepted from repositories. The database
is created with `--build-mode=none` for languages that support it
(JavaScript/TypeScript, Python, Ruby, Go, Java, C#).

## BUILD_REQUIRED (§28)

Languages without a no-build mode (C/C++, Swift) cannot be analyzed
without compiling target code — which the no-code-execution policy
forbids. Those repositories record `BUILD_REQUIRED` and proceed with
the other engines; the platform never builds target code.

## Output

SARIF → the hardened SarifImporter (caps, URI normalization,
codeFlows preserved as dataflow evidence).

## Health

UNAVAILABLE when the binary is absent from the worker host.
