import { Injectable } from "@nestjs/common";
import type { NextFunction, Request, Response } from "express";
import { HealthService } from "./health.service";

/**
 * Minimal Prometheus exposition (Prompt 25 §102–§104): HTTP request counters
 * by method/status class, process gauges, and dependency-up gauges fed by
 * the health service (cached 15s so scrapes cannot stampede dependencies).
 * Labels are bounded (method, status class) — never per-URL or per-tenant,
 * which would explode cardinality and leak tenant structure.
 */
@Injectable()
export class MetricsService {
  private readonly counters = new Map<string, number>();
  private cachedDeps: { at: number; lines: string[] } | null = null;

  constructor(private readonly health: HealthService) {}

  middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      res.on("finish", () => {
        const key = `dsrclone_http_requests_total{method="${req.method}",status_class="${Math.floor(res.statusCode / 100)}xx"}`;
        this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
      });
      next();
    };
  }

  private async dependencyLines(): Promise<string[]> {
    if (this.cachedDeps && Date.now() - this.cachedDeps.at < 15_000) return this.cachedDeps.lines;
    const { checks } = await this.health.check();
    const lines = Object.entries(checks).map(
      ([name, c]) => `dsrclone_dependency_up{dependency="${name}"} ${c.status === "ok" ? 1 : 0}`,
    );
    this.cachedDeps = { at: Date.now(), lines };
    return lines;
  }

  async render(): Promise<string> {
    const mem = process.memoryUsage();
    const lines: string[] = [
      "# HELP dsrclone_http_requests_total HTTP requests by method and status class.",
      "# TYPE dsrclone_http_requests_total counter",
      ...[...this.counters.entries()].map(([k, v]) => `${k} ${v}`),
      "# HELP dsrclone_process_uptime_seconds Process uptime in seconds.",
      "# TYPE dsrclone_process_uptime_seconds gauge",
      `dsrclone_process_uptime_seconds ${Math.floor(process.uptime())}`,
      "# HELP dsrclone_process_memory_bytes Process memory usage by kind.",
      "# TYPE dsrclone_process_memory_bytes gauge",
      `dsrclone_process_memory_bytes{kind="rss"} ${mem.rss}`,
      `dsrclone_process_memory_bytes{kind="heap_used"} ${mem.heapUsed}`,
      "# HELP dsrclone_dependency_up 1 when a checked dependency is reachable.",
      "# TYPE dsrclone_dependency_up gauge",
      ...(await this.dependencyLines()),
    ];
    return lines.join("\n") + "\n";
  }
}
