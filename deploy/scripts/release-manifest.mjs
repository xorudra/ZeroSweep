#!/usr/bin/env node
/**
 * Release manifest generator (Prompt 25 §144–§146).
 * Emits release-manifest.json binding a release to: version, git commit,
 * image references (digests supplied by the build system via IMAGE_DIGEST_*
 * env vars — this script never invents digests), the packaged migration
 * head, the worker version, and the governed tool-inventory count (drift
 * detection: compare inventory + worker version across environments).
 * SBOMs and signatures are produced in CI (syft / cosign); when those tools
 * are absent the manifest says so instead of fabricating references.
 * Usage: ZEROSWEEP_VERSION=25.0.0 node deploy/scripts/release-manifest.mjs
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const git = (args) => {
  try { return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim(); } catch { return null; }
};

const migrationsDir = join(root, "packages/database/prisma/migrations");
const migrations = readdirSync(migrationsDir, { withFileTypes: true })
  .filter((d) => d.isDirectory()).map((d) => d.name).sort();
const seed = readFileSync(join(root, "packages/database/prisma/seed.ts"), "utf8");
const toolSlugs = new Set([...seed.matchAll(/slug: "([a-z0-9-]+)"/g)].map((m) => m[1]));
const heartbeat = readFileSync(join(root, "apps/worker/src/heartbeat/heartbeat.ts"), "utf8");
const workerVersion = /WORKER_VERSION = "([^"]+)"/.exec(heartbeat)?.[1] ?? null;

const images = ["api", "web", "ai", "worker", "scheduler", "migrate"].map((name) => ({
  name: `zerosweep-${name}`,
  reference: process.env[`IMAGE_REF_${name.toUpperCase()}`] ?? null,
  digest: process.env[`IMAGE_DIGEST_${name.toUpperCase()}`] ?? null,
}));

const manifest = {
  product: "ZeroSweep",
  version: process.env.ZEROSWEEP_VERSION ?? null,
  gitCommit: git(["rev-parse", "HEAD"]),
  gitBranch: git(["rev-parse", "--abbrev-ref", "HEAD"]),
  builtAt: new Date().toISOString(),
  images,
  database: {
    migrationCount: migrations.length,
    migrationHead: migrations[migrations.length - 1] ?? null,
  },
  worker: { version: workerVersion },
  toolInventory: { catalogEntries: toolSlugs.size, source: "packages/database/prisma/seed.ts (governed catalog)" },
  sbom: {
    generated: false,
    note: "Generate per-image SBOMs in CI with syft (spdx-json) and attach them to the release; see deploy/scripts/README.md.",
  },
  signatures: {
    signed: false,
    note: "Sign images in CI with cosign keyless/OIDC; verification policy lives in deploy/policies/.",
  },
  verification: {
    imageDigestsRecorded: images.every((i) => i.digest !== null),
    warning: images.some((i) => i.digest === null)
      ? "Some image digests were not supplied by the build system — the release is NOT fully pinned until they are."
      : null,
  },
};

const out = join(root, "release-manifest.json");
writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
console.log(`wrote ${out}`);
console.log(JSON.stringify({ version: manifest.version, gitCommit: manifest.gitCommit, migrationHead: manifest.database.migrationHead, workerVersion, tools: toolSlugs.size }, null, 2));
if (!existsSync(out)) process.exit(1);
