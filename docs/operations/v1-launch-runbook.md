# v1.0 Launch Runbook (Prompt 40 §278/§279)

## Pre-launch
1. Confirm RC status: RC_READY with 0 BLOCKER / 0 CRITICAL open
   (`docs/release/rc1-findings.md`).
2. Run the launch gate evaluation:
   `node scripts/product/launch-gates.mjs --evidence <file> --out release/v1.0`
   — the result must be **V1_READY**; a V1_BLOCKED result names the
   exact gates to close.
3. Verify backups + a fresh isolated restore (Prompt 38 runbooks).
4. Verify production configuration validation passes (P38 §config)
   and product configuration matches `docs/product/configuration.md`.
5. Confirm billing/licensing gate applicability for THIS deployment
   (§268/§269) — NOT_APPLICABLE only when genuinely disabled.

## Launch
6. Deploy the release train (API, worker, web, AI) at the manifest
   version (`release/v1.0/manifest.json`).
7. Run migrations; run the seed (idempotent).
8. Smoke: health, product smoke
   (`scripts/local-stack/product-smoke.mjs`), one governed fixture
   scan end-to-end.
9. Watch the post-launch monitoring checklist (next doc) for the
   first window.

## Rollback (§282)
- Application rollback uses the previous release train; database
  rollback follows the P38 restore procedure.
- Rollback NEVER discards billing/usage events: product tables are
  append-friendly, plan versions are immutable, and metering raw
  events are authoritative (§285). A rollback re-points the app, not
  the ledger.
