-- Launch Safety Standard section G, item 32 (2026-10-11): indexes added
-- from observed API query patterns (tenant-scoped lists ordered by
-- createdAt, finding-timeline lookups by findingId + createdAt, the AI
-- retrieval ORDER BY riskScore within a workspace, and one bare FK
-- children listing). Additive only; no existing index is changed.
-- Plain CREATE INDEX matches every prior migration in this repo and is
-- safe at current table sizes; on a future live-sized table, create the
-- equivalent index CONCURRENTLY outside the migration transaction first.

CREATE INDEX "Finding_workspaceId_riskScore_idx" ON "Finding"("workspaceId", "riskScore");
CREATE INDEX "Assessment_workspaceId_createdAt_idx" ON "Assessment"("workspaceId", "createdAt");
CREATE INDEX "Scan_workspaceId_createdAt_idx" ON "Scan"("workspaceId", "createdAt");
CREATE INDEX "Asset_workspaceId_createdAt_idx" ON "Asset"("workspaceId", "createdAt");
CREATE INDEX "Target_workspaceId_createdAt_idx" ON "Target"("workspaceId", "createdAt");
CREATE INDEX "RemediationCase_workspaceId_createdAt_idx" ON "RemediationCase"("workspaceId", "createdAt");
CREATE INDEX "FindingHistory_findingId_createdAt_idx" ON "FindingHistory"("findingId", "createdAt");
CREATE INDEX "FindingComment_findingId_createdAt_idx" ON "FindingComment"("findingId", "createdAt");
CREATE INDEX "FindingEvidence_findingId_createdAt_idx" ON "FindingEvidence"("findingId", "createdAt");
CREATE INDEX "WirelessStation_accessPointId_idx" ON "WirelessStation"("accessPointId");
