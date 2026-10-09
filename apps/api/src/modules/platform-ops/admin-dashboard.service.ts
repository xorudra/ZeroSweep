import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { HealthService } from "../../health/health.service";
import { requirePlatformPermission } from "./permissions";

/**
 * Admin dashboard aggregates (deployment-level, for the /admin console).
 * Every number is a real row count or a live health check — nothing is
 * estimated, sampled or invented. Windows are explicit: "current period"
 * is the last 7 days, compared against the 7 days before it; a delta is
 * null when the prior window is empty (no baseline, no percentage).
 * Tenant data is aggregated as COUNTS ONLY across organizations — the
 * platform plane never leaks tenant content into the admin console.
 */
@Injectable()
export class AdminDashboardService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly health: HealthService,
  ) {}

  async dashboard(user: RequestUser) {
    requirePlatformPermission(user, "VIEW_PLATFORM_HEALTH");
    const now = new Date();
    const dayMs = 24 * 60 * 60 * 1000;
    const since14 = new Date(now.getTime() - 14 * dayMs);
    const since7 = new Date(now.getTime() - 7 * dayMs);

    const db = this.prisma as unknown as Record<string, { count: (args?: object) => Promise<number> }>;
    const count = (model: string, where?: object) =>
      db[model].count(where ? { where } : undefined);
    const window = async (model: string) => {
      const [cur, prev] = await Promise.all([
        count(model, { createdAt: { gte: since7 } }),
        count(model, { createdAt: { gte: since14, lt: since7 } }),
      ]);
      return { cur, prev, deltaPct: prev === 0 ? null : Math.round(((cur - prev) / prev) * 100) };
    };

    const [
      organizations, users, workspaces, targets, scansTotal, findingsTotal,
      usersW, scansW, findingsW, orgsW,
      scanRows, findingRows, severityRows, scanStatusRows, recentUsers, health, svc,
    ] = await Promise.all([
      count("organization"), count("user"), count("workspace"), count("target"),
      count("scan"), count("finding"),
      window("user"), window("scan"), window("finding"), window("organization"),
      this.prisma.scan.findMany({ where: { createdAt: { gte: since14 } }, select: { createdAt: true } }),
      this.prisma.finding.findMany({ where: { createdAt: { gte: since14 } }, select: { createdAt: true } }),
      this.prisma.finding.groupBy({ by: ["severity"], _count: true }),
      this.prisma.scan.groupBy({ by: ["status"], _count: true }),
      this.prisma.user.findMany({
        orderBy: { createdAt: "desc" }, take: 8,
        select: {
          id: true, name: true, email: true, status: true, isPlatformAdmin: true, createdAt: true, lastLoginAt: true,
          memberships: { take: 1, select: { role: true, organization: { select: { name: true } } } },
        },
      }),
      this.health.check(),
      this.health.serviceChecks(),
    ]);

    const days: string[] = [];
    for (let i = 13; i >= 0; i--) days.push(new Date(now.getTime() - i * dayMs).toISOString().slice(0, 10));
    const bucket = (rows: Array<{ createdAt: Date }>) => {
      const map = new Map(days.map((d) => [d, 0]));
      for (const r of rows) {
        const key = new Date(r.createdAt).toISOString().slice(0, 10);
        if (map.has(key)) map.set(key, (map.get(key) ?? 0) + 1);
      }
      return days.map((d) => map.get(d) ?? 0);
    };
    const byStatus = (rows: Array<{ status: string; _count: number }>) =>
      Object.fromEntries(rows.map((r) => [r.status, r._count]));

    return {
      generatedAt: now.toISOString(),
      counts: { organizations, users, workspaces, targets, scans: scansTotal, findings: findingsTotal },
      windows: { users: usersW, scans: scansW, findings: findingsW, organizations: orgsW },
      series14d: { days, scans: bucket(scanRows as Array<{ createdAt: Date }>), findings: bucket(findingRows as Array<{ createdAt: Date }>) },
      findingsBySeverity: (severityRows as Array<{ severity: string; _count: number }>).map((r) => ({ severity: r.severity, count: r._count })),
      scansByStatus: byStatus(scanStatusRows as Array<{ status: string; _count: number }>),
      recentUsers: (recentUsers as Array<Record<string, unknown>>).map((u) => {
        const m = (u.memberships as Array<{ role: string; organization: { name: string } }> | undefined)?.[0];
        return {
          id: u.id, name: u.name, email: u.email,
          organization: m?.organization?.name ?? null, role: m?.role ?? null,
          status: u.status, isPlatformAdmin: u.isPlatformAdmin === true,
          createdAt: u.createdAt, lastLoginAt: u.lastLoginAt,
        };
      }),
      health: {
        // Infrastructure checks (API/DB/Redis/storage) merged with the
        // HTTP service checks (AI/worker/web) — the Admin Panel's status
        // list is the whole deployment, not just this process's deps.
        status: Object.values({ ...health.checks, ...svc }).some((c) => c.status === "down") ? "degraded" : health.status,
        checks: { ...health.checks, ...svc },
      },
    };
  }
}
