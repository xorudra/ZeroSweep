import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { allowedClassifications } from "../permissions";
import { csvCell } from "../helpers";
import { SearchService } from "../search/search.service";
import { AggregationService } from "../aggregations/aggregation.service";

/** §103: exports are row-limited, classification-checked, tenant-filtered and audited. */
export const EXPORT_ROW_LIMIT = 1000;

@Injectable()
export class ExportService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly search: SearchService,
    private readonly aggregations: AggregationService,
  ) {}

  async exportAnalytics(user: RequestUser, workspace: { id: string }, body: { kind: string; query?: string; view?: string; format: string }) {
    let payload: unknown;
    let rowCount = 0;
    if (body.kind === "SEARCH") {
      const result = await this.search.search(user, workspace, { query: body.query ?? "", pageSize: 100 });
      const rows = result.results.slice(0, EXPORT_ROW_LIMIT);
      rowCount = rows.length;
      payload = body.format === "CSV"
        ? toCsv(rows as unknown as Array<Record<string, unknown>>, ["documentType", "resourceId", "title", "severity", "classification", "riskScore", "updatedAt"])
        : { exportedAt: new Date().toISOString(), rows };
    } else {
      const view = body.view ?? "OVERVIEW";
      const data = await this.viewData(user, workspace.id, view);
      payload = body.format === "CSV"
        ? JSON.stringify(data, null, 2) // views are nested aggregates; CSV applies to row exports — JSON is the honest rendering
        : { exportedAt: new Date().toISOString(), view, data };
      rowCount = 1;
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "ANALYTICS_EXPORTED", resourceType: "AnalyticsExport",
      metadata: { kind: body.kind, view: body.view ?? null, format: body.format, rowCount, rowLimit: EXPORT_ROW_LIMIT, classifications: allowedClassifications(user) },
    });
    return { format: body.format, rowCount, rowLimit: EXPORT_ROW_LIMIT, content: payload };
  }

  private async viewData(user: RequestUser, workspaceId: string, view: string): Promise<unknown> {
    switch (view) {
      case "FINDINGS": return this.aggregations.findingsAnalytics(workspaceId);
      case "ASSETS": return this.aggregations.assetsAnalytics(workspaceId);
      case "RISK": return this.aggregations.riskAnalytics(workspaceId);
      case "DEVSECOPS": return this.aggregations.devsecopsAnalytics(workspaceId);
      case "CLOUD": return this.aggregations.cloudAnalytics(workspaceId);
      case "IDENTITY": return this.aggregations.identityAnalytics(user, workspaceId);
      case "GRC": return this.aggregations.grcAnalytics(workspaceId);
      default: return this.aggregations.overview(workspaceId);
    }
  }
}

export function toCsv(rows: Array<Record<string, unknown>>, columns: string[]): string {
  const lines = [columns.join(",")];
  for (const row of rows) lines.push(columns.map((c) => csvCell(row[c])).join(","));
  return lines.join("\n");
}
