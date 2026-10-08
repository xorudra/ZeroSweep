import { HealthService } from "./health.service";

describe("HealthService", () => {
  it("reports degraded/down dependencies honestly when nothing is reachable", async () => {
    const prismaMock = { $queryRaw: async () => { throw new Error("no db in unit test"); } };
    const svc = new HealthService(prismaMock as never);
    const result = await svc.check();
    expect(result.checks.api.status).toBe("ok");
    expect(result.checks.postgres.status).toBe("down");
    expect(["degraded", "down"]).toContain(result.status);
  });

  it("liveness never depends on dependency state (Prompt 25 §88)", () => {
    const prismaMock = { $queryRaw: async () => { throw new Error("db down"); } };
    const svc = new HealthService(prismaMock as never);
    const live = svc.live();
    expect(live.status).toBe("ok");
    expect(live.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });

  it("readiness is false when a REQUIRED dependency (postgres) is down (Prompt 25 §89)", async () => {
    const prismaMock = { $queryRaw: async () => { throw new Error("db down"); } };
    const svc = new HealthService(prismaMock as never);
    const ready = await svc.ready();
    expect(ready.ready).toBe(false);
    expect(ready.required.postgres.status).toBe("down");
    // Optional dependencies are reported separately and never gate readiness alone.
    expect(ready.optional).toHaveProperty("minio");
    expect(ready.optional).toHaveProperty("ai");
  });
});
