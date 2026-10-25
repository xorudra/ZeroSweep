import { Body, Controller, Delete, Get, Inject, Param, Patch, Post, Query } from "@nestjs/common";
import { sha256Hex } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import {
  aiAskSchema, dateRangeSchema, exportSchema, ingestBatchSchema, reindexSchema,
  retentionPolicySchema, savedQuerySchema, searchRequestSchema, signalStatusSchema, snapshotSchema,
} from "./dto/schemas";
import { requireAnalyticsPermission } from "./permissions";
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
import { AnalyticsCacheService } from "./cache";

/**
 * Security Analytics API (Prompt 27 §26/§98–§103).
 *
 * Every handler resolves the caller's workspace through the tenant
 * helper first — analytics never becomes an authorization bypass:
 * queries, aggregations, search, exports and AI retrieval all run
 * inside the caller's organization/workspace/RBAC/classification
 * context (§ "IMPORTANT").
 */
@Controller("analytics")
export class SecurityAnalyticsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly ingestion: IngestionService,
    private readonly indexing: IndexingService,
    private readonly searchSvc: SearchService,
    private readonly aggregations: AggregationService,
    private readonly attackSurface: AttackSurfaceService,
    private readonly timelines: TimelineService,
    private readonly correlations: CorrelationService,
    private readonly graph: GraphService,
    private readonly savedQueries: SavedQueryService,
    private readonly exportsSvc: ExportService,
    private readonly ai: AiAnalyticsService,
    private readonly retention: RetentionService,
    private readonly healthSvc: AnalyticsHealthService,
    private readonly cache: AnalyticsCacheService,
  ) {}

  private async ws(user: RequestUser, query: unknown) {
    const q = (query ?? {}) as { workspaceId?: string };
    return resolveWorkspace(this.prisma, user, q.workspaceId);
  }

  private scope(user: RequestUser, workspace: { id: string }) {
    return { organizationId: user.organizationId, workspaceId: workspace.id };
  }

  private async cached<T>(user: RequestUser, workspace: { id: string }, view: string, filters: unknown, compute: () => Promise<T>): Promise<T> {
    const key = this.cache.keyFor(user, workspace.id, view, filters);
    const hit = this.cache.get<T>(key);
    if (hit) return hit;
    const value = await compute();
    this.cache.set(user, workspace.id, key, value);
    return value;
  }

  /* ------------------------------ §98 dashboards ------------------------------ */

  @Get("overview")
  async overview(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { days } = parseOrThrow(dateRangeSchema, (query ?? {}) as object);
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "OVERVIEW", { days }, () => this.aggregations.overview(workspace.id, days));
  }

  @Get("findings")
  async findings(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { days } = parseOrThrow(dateRangeSchema, (query ?? {}) as object);
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "FINDINGS", { days }, () => this.aggregations.findingsAnalytics(workspace.id, days));
  }

  @Get("assets")
  async assets(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "ASSETS", {}, () => this.aggregations.assetsAnalytics(workspace.id));
  }

  @Get("attack-surface")
  async attackSurfaceView(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "ATTACK_SURFACE", {}, () => this.attackSurface.dashboard(workspace.id));
  }

  @Post("attack-surface/snapshot")
  async attackSurfaceSnapshot(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    const snapshot = await this.attackSurface.captureSnapshot(workspace.id);
    this.cache.invalidateWorkspace(user, workspace.id);
    return snapshot;
  }

  @Get("risk")
  async risk(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { days } = parseOrThrow(dateRangeSchema, (query ?? {}) as object);
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "RISK", { days }, () => this.aggregations.riskAnalytics(workspace.id, days));
  }

  @Get("devsecops")
  async devsecops(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { days } = parseOrThrow(dateRangeSchema, (query ?? {}) as object);
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "DEVSECOPS", { days }, () => this.aggregations.devsecopsAnalytics(workspace.id, days));
  }

  @Get("cloud")
  async cloud(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { days } = parseOrThrow(dateRangeSchema, (query ?? {}) as object);
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "CLOUD", { days }, () => this.aggregations.cloudAnalytics(workspace.id, days));
  }

  @Get("identity")
  async identity(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "IDENTITY", {}, () => this.aggregations.identityAnalytics(user, workspace.id));
  }

  @Get("grc")
  async grc(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.cached(user, workspace, "GRC", {}, () => this.aggregations.grcAnalytics(workspace.id));
  }

  /* ------------------------------ §99 timelines ------------------------------ */

  @Get("assets/:id/timeline")
  async assetTimeline(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.timelines.assetTimeline(this.scope(user, workspace), id);
  }

  @Get("findings/:id/timeline")
  async findingTimeline(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.timelines.findingTimeline(this.scope(user, workspace), id);
  }

  /* ------------------------------ §100 correlations ------------------------------ */

  @Get("correlations")
  async listCorrelations(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    const { status } = (query ?? {}) as { status?: string };
    return this.correlations.listSignals(workspace.id, status);
  }

  @Get("correlations/:id")
  async correlation(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.correlations.getSignal(workspace.id, id);
  }

  @Patch("correlations/:id")
  async updateCorrelation(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const { status } = parseOrThrow(signalStatusSchema, body);
    const workspace = await this.ws(user, query);
    return this.correlations.setSignalStatus(workspace.id, id, status);
  }

  @Post("correlations/run")
  async runCorrelations(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    const result = await this.correlations.runCorrelations(workspace.id);
    this.cache.invalidateWorkspace(user, workspace.id);
    return result;
  }

  @Post("correlations/rules")
  async createRule(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    const data = body as { name: string; description?: string; conditions: never[]; severity: string; outputType: string };
    return this.correlations.createRule(workspace.id, data);
  }

  /* ------------------------------ §101 attack paths ------------------------------ */

  @Get("attack-paths")
  async attackPaths(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ATTACK_PATHS");
    const workspace = await this.ws(user, query);
    const { status } = (query ?? {}) as { status?: string };
    return this.graph.listAttackPaths(workspace.id, status);
  }

  @Get("attack-paths/:id")
  async attackPath(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ATTACK_PATHS");
    const workspace = await this.ws(user, query);
    const path = await this.graph.getAttackPath(workspace.id, id);
    // §110: attack-path access is audited.
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ATTACK_PATH_ACCESSED", resourceType: "AttackPathCandidate", resourceId: id,
      metadata: { score: path.score, confidence: path.confidence },
    });
    return path;
  }

  @Post("attack-paths/generate")
  async generateAttackPaths(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.graph.generateAttackPaths(workspace.id);
  }

  @Get("graph/traverse")
  async traverse(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    const { startId, maxDepth } = (query ?? {}) as { startId?: string; maxDepth?: string };
    return this.graph.traverse(workspace.id, startId ?? "internet", { maxDepth: maxDepth ? Number(maxDepth) : undefined });
  }

  /* ------------------------------ ingestion / projections ------------------------------ */

  @Post("ingestion/run")
  async runIngestion(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    const result = await this.ingestion.runAll(this.scope(user, workspace));
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ANALYTICS_INGESTION_RUN", resourceType: "SecurityAnalyticsEvent",
      metadata: { stored: result.outbox.stored + result.history.stored, rejected: result.outbox.rejected + result.history.rejected },
    });
    this.cache.invalidateWorkspace(user, workspace.id);
    return result;
  }

  @Post("ingestion/events")
  async ingestEvents(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const { events } = parseOrThrow(ingestBatchSchema, body);
    const workspace = await this.ws(user, query);
    return this.ingestion.ingestBatch(this.scope(user, workspace), events);
  }

  @Post("projections/rebuild")
  async rebuild(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.retention.rebuild(this.scope(user, workspace));
  }

  @Post("snapshots")
  async captureDashboardSnapshot(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const { view } = parseOrThrow(snapshotSchema, body);
    const workspace = await this.ws(user, query);
    const content = await this.exportsSvcView(user, workspace.id, view);
    const row = await this.prisma.analyticsDashboardSnapshot.create({
      data: {
        workspaceId: workspace.id, view, source: "MANUAL",
        content: content as never, contentHash: sha256Hex(JSON.stringify(content)), generatedBy: user.id,
      },
    });
    await this.timelines.captureAssetSnapshots(workspace.id);
    return row;
  }

  private async exportsSvcView(user: RequestUser, workspaceId: string, view: string): Promise<unknown> {
    switch (view) {
      case "FINDINGS": return this.aggregations.findingsAnalytics(workspaceId);
      case "ASSETS": return this.aggregations.assetsAnalytics(workspaceId);
      case "ATTACK_SURFACE": return this.attackSurface.dashboard(workspaceId);
      case "RISK": return this.aggregations.riskAnalytics(workspaceId);
      case "DEVSECOPS": return this.aggregations.devsecopsAnalytics(workspaceId);
      case "CLOUD": return this.aggregations.cloudAnalytics(workspaceId);
      case "IDENTITY": return this.aggregations.identityAnalytics(user, workspaceId);
      case "GRC": return this.aggregations.grcAnalytics(workspaceId);
      default: return this.aggregations.overview(workspaceId);
    }
  }

  /* ------------------------------ saved queries ------------------------------ */

  @Get("saved-queries")
  async listSavedQueries(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "SEARCH_SECURITY");
    const workspace = await this.ws(user, query);
    return this.savedQueries.list(user, workspace.id);
  }

  @Post("saved-queries")
  async createSavedQuery(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "SEARCH_SECURITY");
    const data = parseOrThrow(savedQuerySchema, body);
    const workspace = await this.ws(user, query);
    const row = await this.savedQueries.create(user, workspace.id, data);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SAVED_QUERY_CREATED", resourceType: "SavedSecurityQuery", resourceId: row.id,
      metadata: { visibility: row.visibility },
    });
    return row;
  }

  @Delete("saved-queries/:id")
  async deleteSavedQuery(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "SEARCH_SECURITY");
    const workspace = await this.ws(user, query);
    return this.savedQueries.remove(user, workspace.id, id);
  }

  @Post("saved-queries/:id/run")
  async runSavedQuery(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "SEARCH_SECURITY");
    const workspace = await this.ws(user, query);
    return this.savedQueries.run(user, workspace, id);
  }

  /* ------------------------------ §102 exports ------------------------------ */

  @Post("export")
  async exportAnalytics(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "EXPORT_ANALYTICS");
    const data = parseOrThrow(exportSchema, body);
    const workspace = await this.ws(user, query);
    return this.exportsSvc.exportAnalytics(user, workspace, { kind: data.kind, query: data.query, view: data.view, format: data.format ?? "JSON" });
  }

  /* ------------------------------ §104 AI ------------------------------ */

  @Post("ai/ask")
  async aiAsk(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { question } = parseOrThrow(aiAskSchema, body);
    const workspace = await this.ws(user, query);
    return this.ai.ask(user, workspace, question);
  }

  @Post("ai/trend")
  async aiTrend(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const { question } = parseOrThrow(aiAskSchema, body);
    const workspace = await this.ws(user, query);
    return this.ai.trend(user, workspace, question);
  }

  @Get("ai/attack-path/:id")
  async aiExplainPath(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ATTACK_PATHS");
    const workspace = await this.ws(user, query);
    return this.ai.explainPath(user, workspace, id);
  }

  /* ------------------------------ retention / reindex / health ------------------------------ */

  @Get("retention-policy")
  async getRetention(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.retention.getPolicy(workspace.id);
  }

  @Patch("retention-policy")
  async updateRetention(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const data = parseOrThrow(retentionPolicySchema, body);
    const workspace = await this.ws(user, query);
    return this.retention.upsertPolicy(workspace.id, data);
  }

  @Post("retention/run")
  async runRetention(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    const result = await this.retention.runRetention(workspace.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ANALYTICS_RETENTION_RUN", resourceType: "AnalyticsRetentionPolicy",
      metadata: { ...result },
    });
    return result;
  }

  @Post("reindex")
  async reindex(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const data = parseOrThrow(reindexSchema, body ?? {});
    const workspace = await this.ws(user, query);
    const result = await this.retention.runReindex(this.scope(user, workspace), user.id, data.documentType);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ANALYTICS_REINDEX_RUN", resourceType: "SecuritySearchDocument",
      metadata: { indexed: result.indexed, documentType: data.documentType ?? "ALL" },
    });
    this.cache.invalidateWorkspace(user, workspace.id);
    return result;
  }

  @Post("index")
  async index(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "MANAGE_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.indexing.indexWorkspace(this.scope(user, workspace));
  }

  @Get("health")
  async health(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "VIEW_ANALYTICS");
    const workspace = await this.ws(user, query);
    return this.healthSvc.health(workspace.id);
  }
}

/** §26: enterprise search lives under /security/search. */
@Controller("security")
export class SecuritySearchController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly searchSvc: SearchService,
  ) {}

  @Post("search")
  async search(@CurrentUser() user: RequestUser, @Body() body: unknown, @Query() query: unknown) {
    requireAnalyticsPermission(user, "SEARCH_SECURITY");
    const data = parseOrThrow(searchRequestSchema, body ?? {});
    const q = (query ?? {}) as { workspaceId?: string };
    const workspace = await resolveWorkspace(this.prisma, user, q.workspaceId);
    return this.searchSvc.search(user, workspace, { query: data.query ?? "", sort: data.sort, cursor: data.cursor, pageSize: data.pageSize, group: data.group });
  }

  @Get("search/suggestions")
  async suggestions(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    requireAnalyticsPermission(user, "SEARCH_SECURITY");
    const { q = "", kind, workspaceId } = (query ?? {}) as { q?: string; kind?: string; workspaceId?: string };
    const workspace = await resolveWorkspace(this.prisma, user, workspaceId);
    return this.searchSvc.suggestions(user, workspace, q, kind);
  }
}
