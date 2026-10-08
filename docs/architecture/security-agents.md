# Security agents (Prompt 36 §51–§58)

Agents are bounded orchestrated pipelines, not autonomous actors.

| Agent | Purpose |
|---|---|
| SecurityAnalysisAgent | General grounded analysis over retrieval |
| VulnerabilityAnalysisAgent | Finding + intel + risk explanation |
| RemediationAgent | Remediation drafts + verification recommendations |
| SocInvestigationAgent | Incident timeline + UNVERIFIED hypotheses |
| CloudSecurityAnalysisAgent | Cloud/container asset analysis |
| ApplicationSecurityAgent | Web/API asset analysis |
| SecurityReportAgent | Report-section drafting with fact checks |

## Bounds (§55–§58)

Each definition carries a tool allowlist and hard limits: max steps
(≤8), max tokens, max tool calls (≤12), max duration. Every intended
tool call passes the gateway gate; repeats of the same signature are
loop-detected (threshold 3) and terminate the run. Termination
reasons: COMPLETED, TERMINATED_LOOP, TERMINATED_LIMIT,
TERMINATED_DURATION, BLOCKED. Agent outputs are drafts and
analysis — `executed: false` by construction.
