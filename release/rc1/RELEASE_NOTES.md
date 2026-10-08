# DSRclone RC1 — Release Notes (§300)

**Release:** DSRclone RC1 · **Version:** 1.0.0-rc.1 · **Date:**
2026-10-08 · **Status:** Release Candidate — audited, hardened and
verified end-to-end (Prompt 39). This is the RC freeze of Prompts
1–38, not yet the v1.0 launch (Prompt 40).

## What DSRclone is

A GUI-first platform for **authorized** security assessments: VAPT
orchestration across 100+ governed tools, continuous monitoring,
vulnerability management and intelligence, remediation with verified
closure, SOC/GRC/analytics, and client reporting — one platform,
strictly scope-bound. Nothing scans without a VERIFIED target and an
APPROVED assessment.

## Capabilities (all verified in RC1)

- **Assessment engines:** recon & asset discovery, web/API/network
  VAPT (V1+V2), cloud & Kubernetes & container security, Active
  Directory defensive assessment, mobile & binary static analysis,
  source-code security (SAST/secrets/SCA/SBOM), passive-only wireless,
  controlled security validation with kill switches.
- **Platform:** canonical findings with fingerprint dedup and
  correlation, deterministic explainable Risk Engine V3,
  remediation orchestration with retest-only VERIFIED_FIXED, SLA
  engine, immutable reporting (PDF/HTML/JSON/CSV) + client portal,
  continuous monitoring/scheduler with fire-time re-authorization,
  EASM with a structural discovery→authorization promotion chain.
- **Enterprise:** orgs/workspaces with enforced tenant isolation,
  RBAC + scoped API keys, SSO (OIDC/SAML), MFA (TOTP/WebAuthn),
  SCIM, GRC (8 frameworks, evidence-derived states), security data
  lake + governed query DSL, SOC detections/evidence/response,
  DevSecOps integrations framework.
- **AI copilot:** grounded, citation-bound analyst assistance over
  normalized data only — no execution surface, no scope creation, no
  approvals; degrades to a labelled rules-based mode.
- **Operations:** hardened Compose/Kubernetes deployment artifacts,
  backup/restore/DR, platform-ops with kill switches and measured
  SLOs, honest health/metrics.

## Security architecture (summary)

Verified-target + approved-assessment + scope-snapshot gating at
scan start AND at scheduled fire time AND in the worker before every
execution; policy engines that structurally exclude intrusive/
exploit/brute/DoS automation; secret references only (never
plaintext); redaction before storage, before providers, before
reports; IDs-only queue payloads; tenant isolation enforced in the
query layer and proven by a dedicated test suite + live matrix.

## Deployment modes

Docker Compose (production profile, hardened) or Kubernetes
(Kustomize canonical / Helm equivalent). A Docker-less local
reference stack is included for evaluation (`scripts/local-stack/`).

## Known limitations (§301) — honest list

- **Commercial scanners** (Burp Pro, Nessus, IDA, Binary Ninja,
  PlexTrac…): connectors/descriptors only — bring your own license;
  nothing commercial is bundled.
- **Live third-party transports** (cloud provider APIs, Kubernetes
  API, IdPs, ticketing, intel feeds) are deliberately NOT_CONFIGURED
  until an operator supplies credentials/references; the platform
  reports this honestly rather than simulating results. The
  vulnerability-intelligence production dataset is EMPTY
  (NEVER_SYNCED) until feeds are configured.
- **Wireless** requires operator RF hardware and stays passive-only.
- **Mobile dynamic analysis** requires an authorized lab device and
  recorded authorization; no device transport is bundled.
- **AI providers:** external/LLM transports are NOT_CONFIGURED until
  an operator connects one; the rules-based fallback is labelled as
  such, never presented as AI.
- Dependency note RC1-H1 (Next.js vendored postcss) accepted for RC1
  with a scheduled framework upgrade — see `docs/release/rc1-findings.md`.
- Performance evidence is single-node latency measurement, not a
  capacity claim; `/vulnerabilities` enrichment latency is RC1-M2.

## Verification summary

2,078 TS tests + 6 pytest green · E2E 40/40 · live regression 13/13
scripts (270 checks) · 13/13 release gates PASS · empty-DB migration
clean · backup/restore verified · secret scan clean.
Final status: **RC_READY** (see CHECKLIST.md and manifest.json).
