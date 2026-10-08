# EASM v2 — Enterprise External Attack Surface Management

Prompt 29 adds an EASM workspace on top of the existing DSRclone
platform: EASM programs own root assets (seed domains, organizations,
cloud accounts, IP ranges) and run governed discovery that produces
**candidates**, never scope.

## The one rule everything else serves

```
DISCOVERED ──(ownership evidence)──▶ VERIFIED OWNED ──(separate grant)──▶ AUTHORIZED FOR ACTIVE TESTING
```

- Every discovery result lands as an `EasmAssetCandidate` with
  `activeTestingStatus = NOT_AUTHORIZED`.
- Promotion to the canonical asset inventory (`Asset`) creates the
  target as `DRAFT` with `verified: false` and `scopeStatus:
  PENDING_REVIEW` — the standard VERIFIED + APPROVED assessment gates
  are untouched and remain the only path to any scan.
- Ownership verification and active-testing authorization are two
  different records, two different permissions, usually two different
  people (see `docs/security/easm-authorization-boundary.md`).

## Components

| Layer | Code |
|---|---|
| Pure engine (normalization, ownership, DNS, certs, tech, exposure, drift) | `packages/security-sdk/src/easm/` |
| API module | `apps/api/src/modules/easm/` |
| Web console | `apps/web/src/app/easm/` (8 pages) |
| Data | 23 `Easm*`/related models, migration `20261008060000_easm` |

## Integration with earlier phases

- **RiskEngine V3 (P7)**: EASM derives *signals* and passes them as
  context; it never re-implements risk scoring.
- **SOC (P28)**: sensitive/dangling/unknown exposure raises governed
  alerts through `AlertService.raiseAlert` (fingerprint dedupe +
  suppression), never a parallel alert store.
- **Scheduler (P22)**: continuous EASM is a `SecuritySchedule` row of
  kind `EASM_DISCOVERY`, materialized by an operator tick — no hidden
  daemon. EASM runs are discovery-class only.
- **Data lake (P27)**: drift events use the `easm-drift:` correlation
  fingerprint namespace.
- **Vulnerability intelligence (P11)**: KEV/EOL labels on technologies
  come from linked findings on promoted assets, never guessed.

## Honesty rules

- Source transports are governed adapters behind `EASM_TRANSPORT`.
  In this environment no live source is wired: every unconfigured
  source reports `NOT_CONFIGURED` and a run containing one completes
  as `PARTIAL`, never fake-COMPLETED.
- Lookalike/brand observations are labelled observations, never
  accusations. Takeover candidates are candidates with evidence.
- Screenshots are metadata records here (object storage is not
  provisioned in this environment); raw-evidence access is a separate
  permission and every access attempt is audited.
