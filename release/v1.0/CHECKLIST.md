# ZeroSweep v1.0 — Launch Checklist (Prompt 40 §264–§266)

Every item needs recorded evidence. "Unchecked" means not done —
there is no placeholder success (§297).

## Release identity
- [x] Version advanced to 1.0.0 across the release train + Helm chart
- [x] RC1 baseline: RC_READY, 0 BLOCKER / 0 CRITICAL open
      (`docs/release/rc1-findings.md`)
- [x] `release/v1.0/manifest.json` generated from the gate run
- [x] `release/v1.0/gate-results.json` recorded by
      `scripts/product/launch-gates.mjs`

## Gates (§267)
- [x] RC_SECURITY
- [x] TENANT_ISOLATION
- [x] AUTHORIZATION
- [x] PRODUCT_ENTITLEMENT
- [x] QUOTA
- [x] METERING
- [x] BILLING_SECURITY — NOT_APPLICABLE (no provider configured in the evaluated deployment, §268; machinery implemented + unit-tested)
- [x] LICENSE_SECURITY — NOT_APPLICABLE (license verification not enabled in the evaluated deployment, §269; machinery implemented + unit-tested)
- [x] ONBOARDING
- [x] BACKUP
- [x] RESTORE
- [x] PRODUCTION_DEPLOYMENT
- [x] DOCUMENTATION
- [x] NO_BLOCKER_DEFECTS

## Final status line (exactly one, §270)
- Status: **V1_READY** (evaluated 2026-10-08 by
  `scripts/product/launch-gates.mjs`; see `gate-results.json`).

## Productization specifics
- [x] Example plans seeded; no invented pricing anywhere (§256/§257)
- [x] Billing unconfigured ⇒ NOT_CONFIGURED, never simulated (§21)
- [x] License verification public-key-only; tamper rejected + audited
- [x] Demo mode labelled SYNTHETIC; demo organizations cannot scan (§178)
- [x] Legal pages are labelled DRAFT placeholders (§166)
- [x] No certification claims anywhere (§260)
- [x] No fake customers, testimonials or launch metrics (§297 honesty)
