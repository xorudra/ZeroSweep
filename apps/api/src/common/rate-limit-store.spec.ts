import { rateLimitCheck, rateLimitHit, rateLimitRecord, resetRateLimitStoreForTests } from "./rate-limit-store";

// No REDIS_URL in the test env: these exercise the bounded in-process
// fallback, which must preserve the exact cap semantics of the Redis
// (Lua) path — `limit` admissions per window, decided atomically.
describe("rate-limit store (in-process fallback)", () => {
  beforeEach(() => resetRateLimitStoreForTests());

  it("rateLimitHit admits exactly `limit` requests per window", async () => {
    const key = "hit|203.0.113.9";
    for (let i = 0; i < 3; i++) {
      expect((await rateLimitHit(key, 3, 60_000)).allowed).toBe(true);
    }
    expect((await rateLimitHit(key, 3, 60_000)).allowed).toBe(false);
    expect((await rateLimitHit(key, 3, 60_000)).allowed).toBe(false);
  });

  it("check/record separation counts only recorded attempts (login path)", async () => {
    const key = "login|a@example.com|203.0.113.9";
    expect((await rateLimitCheck(key, 2, 60_000)).allowed).toBe(true);
    expect((await rateLimitCheck(key, 2, 60_000)).allowed).toBe(true); // checks alone never consume
    await rateLimitRecord(key, 60_000);
    await rateLimitRecord(key, 60_000);
    expect((await rateLimitCheck(key, 2, 60_000)).allowed).toBe(false);
  });

  it("keys are independent buckets", async () => {
    await rateLimitHit("hit|198.51.100.1", 1, 60_000);
    expect((await rateLimitHit("hit|198.51.100.1", 1, 60_000)).allowed).toBe(false);
    expect((await rateLimitHit("hit|198.51.100.2", 1, 60_000)).allowed).toBe(true);
  });
});
