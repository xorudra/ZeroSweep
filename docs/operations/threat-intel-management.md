# Threat Intel Management (Prompt 28 operations)

## Sources

Register each feed as a source with a realistic trust level —
trust feeds the deterministic confidence policy, so an inflated
trust score silently inflates every downstream alert. Live
transports are unwired in this environment: the Sync button
records `NOT_CONFIGURED` and imports nothing. That is the honest
state, not an error to work around.

## Imports

- Import recorded STIX bundles or indicator lists from
  `/soc/threat-intelligence`. Imports are deduplicated per
  workspace + type + value; repeat imports add observations
  (provenance), not duplicate indicators.
- Review parse errors after each import — rejected objects are
  reported, never silently dropped or half-stored.
- Check the sync record (`ThreatIntelFeedSync`) for counts:
  in / created / updated / errors.

## Hygiene

- Set `validUntil` on time-boxed indicators; expired indicators
  stop producing active detections automatically (historical
  matches remain visible and flagged).
- Mark bad indicators `FALSE_POSITIVE` or `REVOKED` instead of
  deleting them — the match history must stay explainable.
- Periodically review low-confidence, single-source indicators:
  they enrich events but never raise alerts alone (≥ 40 confidence
  and ACTIVE status required), so a stale noisy feed degrades
  gracefully instead of paging the team.
