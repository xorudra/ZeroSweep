# The finding pipeline: detection → normalization → correlation → risk

Prompt 7 turns raw scanner output into trustworthy, reviewable findings.
The pipeline is deterministic end to end — no AI anywhere in it.

## Stages

```
SAFE_VULNERABILITY_SCAN ──► NORMALIZATION ──► CORRELATION ──► RISK_ANALYSIS ──► REPORT_GENERATION
 (nuclei · nikto ·           (summaries,        (merge dupes,    (deterministic
  testssl · sslyze)           counts)            corroboration)   0–100 scores)
```

1. **Detection.** Adapters run through the standard SDK lifecycle
   (validate → plan → execute → parse → normalize) with per-tool parsers.
   Raw output is preserved as an object-storage artifact with checksum +
   size before anything is derived from it.
2. **Normalization.** Every tool's output becomes the common Finding
   schema: title, description, severity, confidence, affected
   host/endpoint/parameter, vulnerability class, evidence, remediation,
   references. CVE/CWE/CVSS/OWASP are populated **only** when the tool
   output provides them or the curated class taxonomy maps the class —
   never invented from a product name or version string.
3. **Evidence handling.** Evidence snippets are redacted (Authorization,
   cookies, tokens, API keys, passwords), size-capped with a truncation
   marker + checksum of the original, and rendered as inert text
   everywhere (stored-XSS and CSV-formula defenses included). Reference
   URLs are validated (http/https only, no embedded credentials).
4. **Correlation.** Deterministic fingerprints
   (host + port/endpoint + parameter + vuln class + CVE/CWE, **no tool
   component**) group reports of the same underlying issue. Each group
   becomes ONE canonical finding: highest severity wins, missing
   CVSS/CVE/remediation fill in from corroborating sources, and every
   source keeps its own evidence row + fingerprint. Near-misses (same
   class family, different specific class) link as POSSIBLE_DUPLICATE
   instead of merging. Duplicates are marked and their evidence re-homed
   — **findings and evidence are never deleted**.
5. **Confidence.** Starts from the strongest single-source confidence;
   each additional *independent* signature family adds a corroboration
   bonus. Two tools echoing one shared signature add nothing. CONFIRMED
   requires deterministic verification or a human review — agreement
   alone tops out at LIKELY.
6. **Risk.** `risk = base × confidenceFactor × criticalityFactor +
   exposure/verification adjustments`, where base is CVSS×10 when a real
   CVSS exists, else the severity band base. Every score ships with its
   explanation strings. REJECTED (false-positive) findings score 0.
   Asset criticality is user/admin-classified; it is never auto-raised
   for internet-facing assets.

## Review lifecycle

Findings carry a manual validation workflow (OPEN → CONFIRMED /
FALSE_POSITIVE / ACCEPTED_RISK / RESOLVED, reopenable on retest). Every
transition requires a reason, records reviewer + timestamp, appends an
immutable `FindingHistory` event, and writes an audit-log row
(`FINDING_CONFIRMED`, `FINDING_FALSE_POSITIVE`, …). Reviews never modify
the scanner's original evidence.

## Budgets & limits

Per-scan budgets (vuln requests, Nuclei templates, Nikto duration, TLS
services, evidence size, max findings) are clamped to admin caps in
code. Reaching `maxFindings` is recorded as a scan event/metrics entry —
results are never silently discarded.
