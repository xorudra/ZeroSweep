/** The scrape gate: loadEnv() caches per process, so each case builds a
 *  fresh module registry with its environment already in place. */
function freshController() {
  jest.resetModules();
  const { MetricsController } = require("./metrics.controller") as typeof import("./metrics.controller");
  return new MetricsController({ render: async () => "METRICS" } as never);
}

describe("MetricsController gate", () => {
  const ORIGINAL = process.env.METRICS_TOKEN;
  afterAll(() => { if (ORIGINAL === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = ORIGINAL; });

  it("404s when no token is configured (endpoint invisible)", async () => {
    delete process.env.METRICS_TOKEN;
    await expect(freshController().scrape("Bearer anything")).rejects.toMatchObject({ status: 404 });
  });

  it("404s on a wrong or missing token and serves on the right one", async () => {
    process.env.METRICS_TOKEN = "test-metrics-token-0123456789";
    const controller = freshController();
    await expect(controller.scrape("Bearer nope")).rejects.toMatchObject({ status: 404 });
    await expect(controller.scrape(undefined)).rejects.toMatchObject({ status: 404 });
    await expect(controller.scrape("Bearer test-metrics-token-0123456789")).resolves.toBe("METRICS");
  });
});
