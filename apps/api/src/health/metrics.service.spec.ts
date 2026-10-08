import { MetricsService } from "./metrics.service";
import { HealthService } from "./health.service";

describe("MetricsService (Prompt 25 §102)", () => {
  it("renders Prometheus text with bounded labels and process gauges", async () => {
    const prismaMock = { $queryRaw: async () => { throw new Error("no db in unit test"); } };
    const metrics = new MetricsService(new HealthService(prismaMock as never));
    const out = await metrics.render();
    expect(out).toContain("# TYPE dsrclone_http_requests_total counter");
    expect(out).toContain("dsrclone_process_uptime_seconds");
    expect(out).toContain('dsrclone_dependency_up{dependency="postgres"} 0');
    // Cardinality discipline: no per-URL or per-tenant labels anywhere.
    expect(out).not.toMatch(/path=|url=|tenant|organization/);
  });

  it("counts requests by method and status class only", async () => {
    const prismaMock = { $queryRaw: async () => { throw new Error("no db in unit test"); } };
    const metrics = new MetricsService(new HealthService(prismaMock as never));
    const mw = metrics.middleware();
    const handlers: Record<string, () => void> = {};
    const req = { method: "GET" } as never;
    const res = { statusCode: 200, on: (ev: string, fn: () => void) => { handlers[ev] = fn; } } as never;
    mw(req, res, () => undefined);
    handlers.finish?.();
    const out = await metrics.render();
    expect(out).toContain('dsrclone_http_requests_total{method="GET",status_class="2xx"} 1');
  });
});
