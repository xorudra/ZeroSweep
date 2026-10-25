# Burp Suite Professional

Commercial web proxy/scanner — ADMIN_PROVIDED licensed environment (Prompt 8 §9). Passive site-map + issue import via the administrator's bridge; active scanning INTRUSIVE, approval-gated, disabled by default. Unconfigured = NOT_CONFIGURED.

- **Slug:** `burp-suite-professional`
- **Category:** WEB
- **License:** ADMIN_PROVIDED — customer/administrator-supplied license required; ZeroSweep never bundles commercial licenses (§122–§126)
- **Risk level:** MODERATE
- **Requires approval:** yes
- **Availability:** NOT_CONFIGURED

## Installation

Installed and licensed by the customer/administrator in their own environment; ZeroSweep connects through its governed adapter only when configured.

## Worker requirement

Execution mode: ADMIN_PROVIDED; network policy: CUSTOM_ALLOWLIST; default timeout: 1200s.

## Input / Output

Supported targets: WEB_APPLICATION, API. Capabilities: PROXY, PASSIVE_ANALYSIS, SITE_MAP_IMPORT, ISSUE_IMPORT, WEB_CRAWLING, ACTIVE_WEB_SCANNING. Output format: JSON; parser: burp-xml. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.

## Governance

Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).
