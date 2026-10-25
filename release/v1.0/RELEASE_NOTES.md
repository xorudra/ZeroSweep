# ZeroSweep v1.0.0 — Release Notes

**Release train:** Prompts 1–40 complete. Baseline: RC1 (Phase 39,
RC_READY, 0 BLOCKER / 0 CRITICAL open).

## What v1.0 is

ZeroSweep is an authorized automated VAPT / security-assessment
orchestration platform: verified targets and scope only, 100+ tools
via a governed Tool Adapter SDK, isolated workers, normalized
findings with deduplication/correlation, a deterministic risk engine,
an AI layer that works on normalized findings only, and
PDF/HTML/JSON/CSV reporting with a client portal.

## New in the v1.0 phase (Prompt 40)

- **Product modes**: COMMUNITY / SELF_HOSTED / SAAS / ENTERPRISE from
  trusted deployment configuration; one codebase.
- **Plans & entitlements**: versioned plans, immutable plan versions,
  per-feature entitlements + limits, backend-enforced fail-closed
  gating, and the §15 precedence chain. Safety controls can never be
  entitled away.
- **Subscriptions & trials**: full lifecycle states, immediate
  upgrades, downgrade impact previews (data is never deleted),
  trial expiry that preserves data.
- **Billing**: provider-abstracted; signed, replay-protected,
  idempotent webhooks; safe event metadata; card data refused. No
  provider configured ⇒ honestly NOT_CONFIGURED, nothing simulated.
- **Licensing**: Ed25519-signed product licenses; the app verifies
  with the public key only; tamper/expiry/revocation handled with
  grace; license failure never deletes data or blocks export.
- **Usage metering & quotas**: idempotent metering from real rows,
  hourly/daily/period aggregates, check-before-create quota
  enforcement with race-safe reservations and a structured
  QUOTA_EXCEEDED contract; platform-only quota overrides.
- **Onboarding**: transactional signup, single-use email
  verification, 10-step security-first onboarding with a recorded
  authorization attestation and a SAFE default profile.
- **Organization lifecycle**: suspend/cancel/retention/deletion with
  impact previews, approval and legal hold.
- **Platform control plane**: separate platform-admin surface
  (metadata-only organization views), reason-bound tenant-approved
  expiring audited support access. No impersonation, no password or
  secret visibility.
- **Demo mode**: synthetic labelled data; demo organizations can
  never scan.
- **Docs & launch**: full product/getting-started/user/admin/API/
  operations documentation, generated tool docs, status page, safe
  installer, diagnostic bundles (redacted, explicit only) and the
  measured v1.0 launch-gate evaluation.

## Known honest limitations

- Single-region deployment (no active-active multi-region claim).
- Live provider/directory/Kubernetes transports remain deliberately
  unwired in this environment and report NOT_CONFIGURED/UNAVAILABLE.
- Docker is unavailable on the build VM; worker isolation is proven
  via the local stack, and production deployment uses the shipped
  Compose/Helm assets.
- Production CI workflow is staged at `deploy/ci/production-ci.yml`
  (repository token lacks `workflow` scope; see activation note).
- Legal pages are DRAFT placeholders pending the operator's
  counsel-approved text.
- No open-source license file is included for the repository itself:
  that legal choice belongs to the project owner and has not been
  made. (This is unrelated to the product's own licensing machinery
  above.)
