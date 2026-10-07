# GUI-first page map

The user does everything in the web GUI — there is no CLI workflow for users.

| Page | Route | What the user does |
|---|---|---|
| Overview | `/` | Assets, active scans, severity counts, risk score, recent assets/findings, scan history, tool/worker health |
| Targets | `/targets` | Register targets (17 types), start ownership verification |
| Target verification | in Targets flow | DNS TXT / HTTP file instructions + "Check" button, or admin approval |
| Assets | `/assets` | Browse discovered hosts/services/endpoints/technologies |
| Assessments | `/assessments` | Wizard: target type → target → verify → scope (include/exclude hosts, ports, paths) → profile → tools preview → resources/warnings → confirm → create |
| Scans | `/scans` | Scan list + live scan view (stage pipeline, current tool, counters, elapsed, emergency stop) via realtime events in later phases |
| Findings | `/findings` | Filter/triage normalized findings, evidence, CVSS/CVE/CWE/OWASP, remediation, duplicate grouping |
| Reports | `/reports` | Generate/download PDF/HTML/JSON/CSV reports |
| Tools | `/tools` | Catalog with category/health/risk/license filters; enable/disable (admin). No run/command button exists |
| Integrations | `/integrations` | DefectDojo/Faraday/Dradis/PlexTrac/Serpico + Shodan/Censys connectors |
| Credentials | Settings / API | Metadata + secret reference form only |
| Audit Logs | `/audit-logs` | Review every security-relevant action |
| Settings | `/settings` | Organization, workspaces, roles, schedules, notifications, safety defaults |

CLI equivalents simply do not exist for users: "run a scanner" = profile +
Start Scan button; "add a tool" = adapter registry entry; "read raw output" =
evidence/artifact viewer with redaction; "schedule" = schedule UI;
"add a key" = encrypted-reference credentials form.
