# KEV Intelligence (Prompt 30 §23–§27)

- `KevRecord` carries the catalog lifecycle: `status` ACTIVE/REMOVED, `removedAt`, `catalogSource`. Retractions are first-class data, not deletions (§23/§24).
- Import semantics: a **full-catalog** import treats absence as removal; a partial excerpt never removes anything. Transitions write immutable `KevCatalogEvent` rows (ADDED/UPDATED/REMOVED) and audit `KEV_ADDED`/`KEV_REMOVED`.
- On ADDED (§26): every finding referencing the CVE is re-enriched in its own workspace, Risk Engine V3 recalculates, score movements land in `IntelligenceRiskHistory`, and the Prompt 22 `NotificationRouterService` routes a `KEV_AFFECTS_ENVIRONMENT` event for workspaces holding internet-facing or critical-asset exposure (§27) — policy (channels, thresholds, quiet hours) stays with the notification policies, not with the importer.
- The KEV console joins catalog state to workspace exposure only: due dates, overdue flags, ransomware association and required actions come verbatim from catalog records.
