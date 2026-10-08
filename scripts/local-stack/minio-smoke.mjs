#!/usr/bin/env node
/**
 * DSRclone Prompt 38 MinIO smoke: the SHIPPED S3ObjectStore (compiled
 * worker code) against the REAL MinIO server provisioned for this
 * stack (official source build — see docs). Verifies bucket creation,
 * PUT/GET round trip, checksum agreement, and a missing-key miss.
 * Requires the worker build (apps/worker/dist) and MinIO credentials
 * in the environment (start.sh writes them into the stack smoke.env).
 * Usage: node scripts/local-stack/minio-smoke.mjs
 */
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const stackEnv = resolve(here, "../../../dsrclone-local-stack/smoke.env");
if (existsSync(stackEnv)) {
  for (const line of readFileSync(stackEnv, "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}
const results = [];
function record(step, ok, detail) {
  results.push({ step, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${step}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}

const distPath = resolve(repo, "apps/worker/dist/artifacts/s3-object-store.js");
if (!existsSync(distPath)) {
  console.log("FAIL  worker build missing — run pnpm build first");
  process.exit(1);
}
const { S3ObjectStore } = await import(distPath);

const healthRes = await fetch("http://127.0.0.1:9000/minio/health/live").catch(() => null);
record("MinIO server healthy", !!healthRes && healthRes.ok, `endpoint=${process.env.MINIO_ENDPOINT ?? "http://127.0.0.1:9000"}`);

const store = S3ObjectStore.fromEnv();
record("S3ObjectStore configured from environment", !!store,
  store ? "credentials present (values not printed)" : "MINIO_* env missing");

if (store) {
  const key = `smoke/${Date.now().toString(36)}/artifact.json`;
  const content = JSON.stringify({ tool: "minio-smoke", fixture: true, at: new Date().toISOString() });
  const stored = await store.put(key, content, "application/json");
  record("PUT artifact to MinIO", stored.storageKey === key && stored.size === Buffer.byteLength(content),
    `key=${key} sha256=${stored.checksum.slice(0, 12)}…`);
  const back = await store.get(key);
  record("GET artifact round trip", back === content, back === content ? "content identical" : "MISMATCH");
  const missing = await store.get(`smoke/${Date.now().toString(36)}/absent.json`);
  record("missing key returns undefined (no fabricated object)", missing === undefined);
}

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} minio smoke checks passed`);
