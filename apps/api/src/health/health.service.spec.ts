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
});
