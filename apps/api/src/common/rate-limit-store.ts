import Redis from "ioredis";
import { rateLimitDecision, type AttemptBucket } from "@zerosweep/security-sdk";

/**
 * Shared rate-limit counters (security audit 2026-10-16 run-2).
 *
 * Run-1 fixed the in-memory limiter's unbounded growth; the residual was
 * that counters were per-process, so a multi-replica deployment silently
 * multiplied every limit by the replica count. Counters now live in
 * Redis (REDIS_URL is configured in every shipped topology — the queues
 * already depend on it), stored as {count, windowStartMs} JSON with the
 * window as TTL, preserving the exact check/record semantics of
 * rateLimitDecision. When Redis is not ready or errors, the limiter
 * degrades to a bounded in-process bucket set — never to open, never to
 * a crashed request.
 */
let client: Redis | null | undefined;
function redis(): Redis | null {
  if (client !== undefined) return client;
  const url = process.env.REDIS_URL;
  if (!url) {
    client = null;
    return client;
  }
  try {
    const c = new Redis(url, {
      maxRetriesPerRequest: 0,
      connectTimeout: 500,
      retryStrategy: (times) => Math.min(times * 200, 5_000),
    });
    c.on("error", () => undefined);
    client = c;
  } catch {
    client = null;
  }
  return client;
}

const memory: AttemptBucket[] = [];
const MAX_MEMORY_BUCKETS = 100_000;

/** Atomic read-modify-write for the Redis bucket (security audit
 *  2026-10-16 run-3): a GET→SET pair from concurrent requests loses
 *  increments, so the whole window check + increment + TTL runs as one
 *  Lua script on the server. Returns the post-increment count. */
const RECORD_LUA = `
local raw = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
if raw then
  local b = cjson.decode(raw)
  if now - b.windowStartMs < window then
    local ttl = window - (now - b.windowStartMs)
    redis.call('SET', KEYS[1], cjson.encode({count = b.count + 1, windowStartMs = b.windowStartMs}), 'PX', ttl)
    return b.count + 1
  end
end
redis.call('SET', KEYS[1], cjson.encode({count = 1, windowStartMs = now}), 'PX', window)
return 1
`;

function memoryRecord(key: string, windowMs: number): void {
  const now = Date.now();
  const bucket = memory.find((b) => b.key === key && now - b.windowStartMs < windowMs);
  if (bucket) {
    bucket.count += 1;
    return;
  }
  if (memory.length >= MAX_MEMORY_BUCKETS) memory.splice(0, memory.length - MAX_MEMORY_BUCKETS + 1);
  memory.push({ key, count: 1, windowStartMs: now });
}

export async function rateLimitCheck(
  key: string,
  limit: number,
  windowMs: number,
): Promise<{ allowed: boolean; retryAfterMs: number }> {
  const r = redis();
  if (r && r.status === "ready") {
    try {
      const raw = await r.get(`ratelimit:${key}`);
      if (raw) {
        const bucket = JSON.parse(raw) as { count: number; windowStartMs: number };
        const now = Date.now();
        if (now - bucket.windowStartMs < windowMs) {
          return bucket.count >= limit
            ? { allowed: false, retryAfterMs: windowMs - (now - bucket.windowStartMs) }
            : { allowed: true, retryAfterMs: 0 };
        }
      }
      return { allowed: true, retryAfterMs: 0 };
    } catch {
      /* fall through to the in-process buckets */
    }
  }
  return rateLimitDecision(memory, key, Date.now(), limit, windowMs);
}

export async function rateLimitRecord(key: string, windowMs: number): Promise<void> {
  const r = redis();
  if (r && r.status === "ready") {
    try {
      await r.eval(RECORD_LUA, 1, `ratelimit:${key}`, String(Date.now()), String(windowMs));
      return;
    } catch {
      /* fall through to the in-process buckets */
    }
  }
  memoryRecord(key, windowMs);
}

/** Atomic check-and-record for limiters that count every request (the
 *  global middleware, signup): one Lua round trip decides on the
 *  post-increment count, so parallel requests can neither lose an
 *  increment nor both slip past the cap on a stale read. */
export async function rateLimitHit(
  key: string,
  limit: number,
  windowMs: number,
): Promise<{ allowed: boolean; retryAfterMs: number }> {
  const r = redis();
  if (r && r.status === "ready") {
    try {
      const count = Number(await r.eval(RECORD_LUA, 1, `ratelimit:${key}`, String(Date.now()), String(windowMs)));
      return { allowed: count <= limit, retryAfterMs: 0 };
    } catch {
      /* fall through to the in-process buckets */
    }
  }
  const decision = rateLimitDecision(memory, key, Date.now(), limit, windowMs);
  if (decision.allowed) memoryRecord(key, windowMs);
  return decision;
}

/** Test hook: drop the shared client + buckets between suites. */
export function resetRateLimitStoreForTests(): void {
  if (client) void client.quit().catch(() => undefined);
  client = undefined;
  memory.length = 0;
}
