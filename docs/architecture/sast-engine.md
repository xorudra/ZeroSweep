# SAST Engine (Prompt 12 §20–§35)

Static analysis runs over the immutable snapshot with a **governed,
pinned ruleset policy** — the same governance style as the Nuclei
template policy (Prompt 7): rule packs and query suites are selected
from an approved catalog by profile and detected language; arbitrary
rule paths, repository-supplied rules and ad-hoc queries are rejected.

## Tools

| Tool | Engine | Governed surface |
| --- | --- | --- |
| Semgrep | pattern + taint rules | approved pack catalog (`p/security-audit`, `p/owasp-top-ten`, language packs, `p/secrets`) resolved per profile/language |
| CodeQL | query suites | `security-extended` suites; languages without a no-build mode (C/C++, Swift) end `BUILD_REQUIRED` — target code is never built |
| Bandit | Python AST checks | fixed check set, JSON output |
| Brakeman | Rails framework analysis | fixed warning classes |
| SpotBugs | Java bytecode/text analysis | SECURITY category + FindSecBugs patterns only; style/correctness bugs are counted as skipped non-security issues |
| SonarQube | connector (admin-registered instance) | vulnerabilities → findings; **security hotspots → REVIEW_REQUIRED, never auto-promoted**; code smells and non-security bugs are never vulnerabilities (§27) |

SARIF results from any tool enter through the reusable hardened
**SarifImporter** (§31/§32): 25 MB / 10,000-result caps, URI
normalization to repository-relative paths, hostile URIs dropped.

## Finding shape (§59–§68)

Every SAST finding carries: repository-relative `filePath`, line/column
range, `ruleId`, a **redacted minimal snippet** (secrets redacted before
storage, capped length), CWE/OWASP only from tool output or curated
mappings, and dataflow steps (`codeFlow`) when the tool provides them.
Fingerprints hash repository + path + rule + normalized code context —
**never line numbers** — so findings survive line movement between
snapshots (§64/§65). Cross-tool merging is conservative: identical
fingerprints merge always; SAST findings from different tools merge only
with evidence beyond a shared CWE (same file, same CWE, line proximity)
(§66). Generated/vendored code is classified and reported with lower
default priority, never silently dropped (§87/§88).
