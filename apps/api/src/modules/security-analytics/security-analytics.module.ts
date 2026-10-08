import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { SecurityAnalyticsController, SecuritySearchController } from "./security-analytics.controller";
import { AnalyticsCacheService } from "./cache";
import { AnalyticsStoreService } from "./storage/analytics-store.service";
import { IngestionService } from "./ingestion/ingestion.service";
import { IndexingService } from "./search/indexing.service";
import { SearchService } from "./search/search.service";
import { AggregationService } from "./aggregations/aggregation.service";
import { AttackSurfaceService } from "./attack-surface/attack-surface.service";
import { TimelineService } from "./timelines/timeline.service";
import { CorrelationService } from "./correlation/correlation.service";
import { GraphService } from "./graph/graph.service";
import { SavedQueryService } from "./saved-queries/saved-query.service";
import { ExportService } from "./exports/export.service";
import { AiAnalyticsService } from "./ai/ai-analytics.service";
import { RetentionService } from "./retention/retention.service";
import { AnalyticsHealthService } from "./health/health.service";

/**
 * Prompt 27 — Security Data Lake, Advanced Analytics, Attack Surface
 * Intelligence & Enterprise Search. Layers over the existing event
 * bus/outbox, finding history, posture snapshots and reporting
 * discipline: projections are derived, operational tables stay
 * authoritative (§3), and every read path is tenant/RBAC/
 * classification scoped before retrieval.
 */
@Module({
  imports: [AuditModule],
  controllers: [SecurityAnalyticsController, SecuritySearchController],
  providers: [
    AnalyticsCacheService, AnalyticsStoreService, IngestionService,
    IndexingService, SearchService, AggregationService, AttackSurfaceService,
    TimelineService, CorrelationService, GraphService, SavedQueryService,
    ExportService, AiAnalyticsService, RetentionService, AnalyticsHealthService,
  ],
  exports: [IngestionService, SearchService, AggregationService],
})
export class SecurityAnalyticsModule {}
