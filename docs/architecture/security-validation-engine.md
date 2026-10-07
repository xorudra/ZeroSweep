# Security Validation Engine (Prompt 16)

## Purpose

DSRclone validates findings to increase **confidence** in scanner
results:

```
Finding → safe-validation check → authorization → scope →
risk classification → approval → controlled validation →
evidence → confidence update → report
```

Validation is **not** autonomous exploitation. A failed validation is
not automatically a false positive, and validation confidence is never
equated with severity (a LOW finding may be VERIFIED; a CRITICAL
finding may be INCONCLUSIVE).

## Components

| Component | Location | Role |
| --- | --- | --- |
| Validator catalog | `packages/security-sdk/src/validation/catalog.ts` | Closed allowlist of governed validators; technique classification |
| Plan builder | `…/validation/plan.ts` | Fixed workflow DAG + plan hash binding |
| Policy engine | `…/validation/policy.ts` | ALLOW / DENY / REQUIRE_APPROVAL decisions |
| Budget engine | `…/validation/budget.ts` | Hard-limit clamping, consumption tracking, rate limits |
| Scope revalidation | `…/validation/scope-revalidation.ts` | Just-before-execution scope + DNS checks |
| Evidence pipeline | `…/validation/evidence.ts` | Redaction, checksums, proof of validation |
| Kill switch | `…/validation/kill-switch.ts` | Level matching (global → session) |
| Callback service | `…/validation/callback.ts` + API service | Token issue/verify, tenant/session binding |
| Workflow service | `apps/api/src/modules/security-validation/` | Requests, approvals, policies, sessions, reports |
| Validation runner | `apps/worker/src/executors/validation-runner.ts` | Isolated worker execution with full re-checks |

## The governed validator catalog

Only these validators exist. Anything outside the catalog is
unrepresentable as a plan and refused at execution time as well
(defense in depth).

| Validator | Domain | Method |
| --- | --- | --- |
| header-recheck | web | repeat the approved HTTP observation, confirm the header state |
| tls-recheck | web/TLS | TLS configuration re-observation (testssl/SSLyze class) |
| endpoint-exposure-recheck | web | confirm an endpoint is still exposed |
| nuclei-recheck | web | repeat an **admin-approved** Nuclei detection template only |
| service-presence-recheck | network | confirm port/service/TLS/banner |
| api-safe-recheck | api | non-destructive authz/header/schema observation |
| cloud-config-recheck | cloud | READ_ONLY configuration confirmation (Prowler class) |
| kubernetes-posture-recheck | kubernetes | posture confirmation (Kubescape class) |
| source-recheck | source | repeat the governed SAST/SCA rule |
| container-image-recheck | container | digest/package/CVE confirmation (Trivy class) |
| ad-posture-recheck | directory | read-only posture confirmation (PingCastle class) |

The `SecurityValidator` interface is `supportsFinding` /
`classifyRisk` / `validatePolicy` / `prepare` / `execute` /
`parseEvidence` / `cleanup`. The `ValidationTransport` it executes
through has **read-only methods only** (HTTP GET observation, TLS
inspection, service probe, configuration check, scanner recheck) —
there is no write, exploit, or arbitrary-request capability to call.

## Prohibited automation

Techniques are classified at plan time, at API intake, and again in the
worker. `PROHIBITED_AUTOMATION` covers: password spraying, credential
stuffing, credential dumping, Kerberoasting, AS-REP roasting, NTLM
poisoning/relay, DCSync, ticket forging, privilege escalation, lateral
movement, persistence, database dumping/extraction, remote command
execution, malware deployment, destructive testing, SQL data
extraction, cookie/session theft, SSRF to metadata/internal services,
and arbitrary file/secret retrieval. These can never be planned,
approved, or executed — including with LAB approval.

Offensive tools (NetExec, Impacket, Certipy, Kerbrute, Responder,
PowerView, Metasploit Framework, Pacu) are registered in a **separate
offensive registry** as metadata only — classification
`OFFENSIVE_SECURITY_TOOL`, execution `DISABLED`, manual-only. Ordinary
scan orchestration never invokes them; no adapter exists for any of
them. Metasploit-class frameworks are never executors in DSRclone.

## Confidence model

`UNVERIFIED → LIKELY → VERIFIED`, or `INCONCLUSIVE`. Only a reproduced
safe validation (or an analyst's VERIFIED manual record) sets
`VERIFIED` and the finding's `CONFIRMED` verification status. Outcomes
`NOT_REPRODUCED`, `FIXED`, `TARGET_CHANGED`, `VALIDATION_BLOCKED` and
`INCONCLUSIVE` set confidence `INCONCLUSIVE` only — the original
scanner evidence is never overwritten.

## Validation vs retest

Validation increases confidence in the **initial** finding; a retest
(Prompt 11) verifies **remediation**. They are different workflows with
different records.
