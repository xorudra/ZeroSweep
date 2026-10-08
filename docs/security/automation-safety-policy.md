# Automation Safety Policy (Prompt 22 §9–§11)

Unattended automation is a **closed** set. `classifyProfile` in
`packages/security-sdk/src/continuous/safety.ts` maps every scan
profile to one of four classes:

| Class | Meaning | Examples |
| --- | --- | --- |
| SAFE_AUTOMATED | may run unattended under schedule | PASSIVE_RECON, WEB_BASELINE, API_ASSESSMENT, NETWORK_DISCOVERY, NETWORK_BASELINE, source/container/Kubernetes/cloud/AD baselines, MOBILE_STATIC_*, BINARY_* static family, WIRELESS_PASSIVE_* |
| APPROVAL_REQUIRED | human approval per engagement; never unattended | WEB_COMPREHENSIVE, NETWORK_COMPREHENSIVE, NETWORK_INTERNAL, DOCKER_HOST_BASELINE, CLOUD_NATIVE_FULL, WIRELESS_LAB_VALIDATION |
| MANUAL_ONLY | analyst-driven only | CUSTOM, and **any unknown profile (fail closed)** |
| PROHIBITED_AUTOMATION | can never be scheduled | BINARY_CONTROLLED_DEBUG, MOBILE_DYNAMIC_CONTROLLED, MOBILE_FULL_CONTROLLED + the §11 name list |

The §11 never-schedule list — password spraying, credential
stuffing, brute force, Kerberoasting, AS-REP roasting, NTLM relay,
credential dumping, RCE exploitation, privilege escalation, lateral
movement, persistence, deauthentication, evil-twin AP, Wi-Fi
cracking, arbitrary Frida scripts, arbitrary debuggers, destructive
API operations — is matched by `classifyAutomationName` and refused
wherever a name can enter the system (policies, schedules,
auto-retest eligibility).

Enforcement points, all covered by tests:

1. Monitoring policy creation (profile must classify schedulable).
2. Schedule creation (assessment profile snapshot re-classified;
   authorization verified at creation, §8).
3. Every fire time (stored profile re-classified again — a profile
   whose classification tightens later stops firing).
4. Auto-retest eligibility (§51–§53): RetestRouter route + Prompt 16
   SAFE validator + exclusion families.
5. Workflow actions: REQUEST_SAFE_RETEST passes through the same
   eligibility gate; no workflow action can execute code.

`safeOnly` on a monitoring policy cannot be set to false — the API
refuses; continuous monitoring is safe-only by construction.
