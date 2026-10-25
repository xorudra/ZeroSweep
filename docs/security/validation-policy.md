# Validation Policy (Prompt 16 §5–§7, §62–§68)

## Risk classes

| Class | Automated default | Examples |
| --- | --- | --- |
| SAFE | Allowed | repeat HTTP request, verify header, confirm TLS, check exposed service, version evidence, approved Nuclei detection repeat, public cloud config confirm, K8s posture confirm, SAST rule repeat, dependency presence check |
| LOW_IMPACT | Approval in production | slightly heavier observations within strict budgets |
| REVIEW_REQUIRED | Always approval | anything ZeroSweep cannot prove is safe by construction (incl. every unknown technique name) |
| INTRUSIVE | Denied by default | only the §63 LAB architecture: explicit authorization + specific scope + named approver + short expiry + isolated environment. **No dangerous exploit modules are implemented.** |
| PROHIBITED_AUTOMATION | Always denied | §97 list — never planned, never approved, never executed |

Default automated validation is **SAFE only**. Organization production
policy defaults to `SAFE_ONLY`.

Unknown technique names classify as `REVIEW_REQUIRED`, never SAFE —
safety is proven by the catalog, not assumed.

## Policy decisions

`ValidationPolicyEngine.evaluate()` returns `ALLOW`, `DENY`, or
`REQUIRE_APPROVAL` with a machine-readable reason code
(`TARGET_NOT_VERIFIED`, `ASSESSMENT_NOT_APPROVED`,
`OUT_OF_SCOPE_DESTINATION`, `PROHIBITED_AUTOMATION`,
`VALIDATOR_NOT_ALLOWED`, `APPROVAL_EXPIRED`, `PLAN_HASH_MISMATCH`,
`APPROVAL_SCOPE_MISMATCH`, `SEPARATION_OF_DUTIES`, …). Denied requests
are persisted as BLOCKED and audited; policy denials are an
observability metric, not an error to hide.

## Approvals

- Specific: target + finding + technique, bound by plan hash.
- No blanket approvals exist.
- Expiry: workspace-configured (default 60 min; INTRUSIVE 15 min).
- Separation of duties for higher-risk classes (workspace policy,
  default on).
- High-criticality assets require approval even for LOW_IMPACT.

## Environments

`PRODUCTION` is the default. `LAB` must be **explicitly marked** on the
request — it is never inferred from a hostname, IP, or target name.

## Budgets and limits

Every validation carries a budget: max requests, duration,
concurrency, bytes, redirects, endpoints, targets. Administrator hard
limits override organization, workspace, request, plan and validator
layers (clamped at plan time, enforced again in the worker). Rate
limits apply per organization, workspace, target, validator and
worker. Every validation process has a hard dead-man timeout.

## Permissions (§62)

`REQUEST_SECURITY_VALIDATION`, `APPROVE_SECURITY_VALIDATION`,
`RUN_SAFE_VALIDATION`, `CANCEL_VALIDATION`, `VIEW_VALIDATION_EVIDENCE`,
`ADD_MANUAL_VALIDATION`, `MANAGE_VALIDATION_POLICY`,
`USE_INTRUSIVE_VALIDATION` (names the LAB architecture permission;
granting it enables no exploit capability, because none exists).

## What is never implemented (§97)

Password spraying, credential stuffing, credential dumping,
Kerberoasting, AS-REP roasting, NTLM poisoning/relay, DCSync, ticket
forging, privilege escalation, lateral movement, persistence, database
dumping, remote command execution, malware deployment, destructive
testing. These are not features awaiting configuration — they are
policy-excluded by design and enforced in code with tests.
