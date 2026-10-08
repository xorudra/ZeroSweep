import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { createHash } from "node:crypto";
import { S3ObjectStore } from "./s3-object-store";

/**
 * S3ObjectStore against a minimal in-process S3 stub (Prompt 38 §58):
 * verifies SigV4 authorization is attached to every request, bucket
 * auto-creation, and a PUT→GET round trip with checksum agreement.
 * The same class is exercised against the real MinIO server in the
 * local-stack smoke (scripts/local-stack/minio-smoke.mjs).
 */
describe("S3ObjectStore (SigV4, stub S3)", () => {
  let server: Server;
  let endpoint: string;
  const objects = new Map<string, Buffer>();
  const seenAuth: string[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      seenAuth.push(String(req.headers.authorization ?? ""));
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        const path = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
        if (req.method === "HEAD") { res.writeHead(objects.size || path !== "/bucket/" ? 200 : 404); res.end(); return; }
        if (req.method === "PUT" && path === "/bucket") { res.writeHead(200); res.end(); return; }
        if (req.method === "PUT") { objects.set(path, body); res.writeHead(200); res.end(); return; }
        if (req.method === "GET") {
          const found = objects.get(path);
          if (!found) { res.writeHead(404); res.end(); return; }
          res.writeHead(200, { "content-type": "application/json" }); res.end(found); return;
        }
        res.writeHead(405); res.end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    endpoint = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  });

  afterAll(async () => { await new Promise<void>((resolve) => server.close(() => resolve())); });

  it("signs requests and round-trips an artifact with matching checksum", async () => {
    const store = new S3ObjectStore({ endpoint, bucket: "bucket", accessKey: "key", secretKey: "secret" });
    const content = JSON.stringify({ tool: "fixture", ok: true });
    const stored = await store.put("scans/s1/executions/e1/raw.json", content, "application/json");
    expect(stored.checksum).toBe(createHash("sha256").update(content).digest("hex"));
    expect(stored.size).toBe(Buffer.byteLength(content));
    expect(await store.get("scans/s1/executions/e1/raw.json")).toBe(content);
    expect(await store.get("scans/nope/raw.json")).toBeUndefined();
    expect(seenAuth.length).toBeGreaterThanOrEqual(3);
    expect(seenAuth.every((a) => a.startsWith("AWS4-HMAC-SHA256 Credential=key/"))).toBe(true);
    expect(seenAuth.every((a) => a.includes("SignedHeaders="))).toBe(true);
  });

  it("fromEnv returns undefined without endpoint and credentials", () => {
    expect(S3ObjectStore.fromEnv({})).toBeUndefined();
    expect(S3ObjectStore.fromEnv({ MINIO_ENDPOINT: "http://127.0.0.1:9000" })).toBeUndefined();
    expect(S3ObjectStore.fromEnv({
      MINIO_ENDPOINT: "http://127.0.0.1:9000", MINIO_ROOT_USER: "u", MINIO_ROOT_PASSWORD: "p",
    })).toBeInstanceOf(S3ObjectStore);
  });
});
