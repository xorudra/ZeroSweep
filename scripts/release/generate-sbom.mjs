#!/usr/bin/env node
/**
 * Release SBOM + license inventory (Prompt 39 §184/§186/§265).
 *
 * Dependency-free generator: walks the actually-installed tree
 * (node_modules/.pnpm) so the SBOM describes what is installed from the
 * committed lockfile, not what a manifest merely requests. Emits a
 * CycloneDX 1.5 document and a flat license inventory.
 *
 * Usage: node scripts/release/generate-sbom.mjs [outDir]
 *   outDir defaults to release/rc1/security-results
 */
import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const outDir = process.argv[2] ?? join(root, "release/rc1/security-results");
const pnpmDir = join(root, "node_modules/.pnpm");

function parseDirName(dir) {
  // pnpm .pnpm layout: name@version[_peer...]; the peer suffix starts at
  // the first "_" and may itself contain "@" — discard it first. Scoped
  // packages are encoded @scope+name@version.
  const base = dir.split("_")[0];
  let name, version;
  if (base.startsWith("@")) {
    const at = base.indexOf("@", 1);
    if (at < 0) return null;
    name = base.slice(0, at).replace("+", "/");
    version = base.slice(at + 1);
  } else {
    const at = base.lastIndexOf("@");
    if (at <= 0) return null;
    name = base.slice(0, at);
    version = base.slice(at + 1);
  }
  if (!/^\d/.test(version)) return null;
  return { name, version };
}

const seen = new Map();
if (existsSync(pnpmDir)) {
  for (const dir of readdirSync(pnpmDir)) {
    const parsed = parseDirName(dir);
    if (!parsed) continue;
    const key = `${parsed.name}@${parsed.version}`;
    if (seen.has(key)) continue;
    let license = "UNKNOWN";
    let description = "";
    const pkgPath = join(pnpmDir, dir, "node_modules", parsed.name, "package.json");
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      const lic = pkg.license ?? pkg.licenses;
      license = typeof lic === "string" ? lic : Array.isArray(lic) ? lic.map((l) => l?.type ?? "UNKNOWN").join(" OR ") : lic?.type ?? "UNKNOWN";
      description = typeof pkg.description === "string" ? pkg.description.slice(0, 300) : "";
    } catch { /* metadata unavailable — license stays UNKNOWN, honestly */ }
    seen.set(key, { ...parsed, license, description });
  }
}

const components = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name)).map((c) => ({
  type: "library",
  "bom-ref": `pkg:npm/${encodeURIComponent(c.name)}@${c.version}`,
  name: c.name,
  version: c.version,
  ...(c.description ? { description: c.description } : {}),
  licenses: [{ expression: c.license }],
  purl: `pkg:npm/${encodeURIComponent(c.name)}@${c.version}`,
}));

const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [{ vendor: "DSRclone", name: "generate-sbom.mjs (Prompt 39)", version: "1.0.0" }],
    component: { type: "application", name: "dsrclone", version: "1.0.0-rc.1" },
  },
  components,
};
writeFileSync(join(outDir, "sbom.cyclonedx.json"), JSON.stringify(sbom, null, 2));
writeFileSync(join(outDir, "license-inventory.json"), JSON.stringify(
  [...seen.values()].sort((a, b) => a.name.localeCompare(b.name)).map(({ name, version, license }) => ({ name, version, license })), null, 2));
console.log(`SBOM: ${components.length} components -> ${join(outDir, "sbom.cyclonedx.json")}`);
const unknown = components.filter((c) => c.licenses[0].expression === "UNKNOWN").length;
console.log(`license inventory written; UNKNOWN licenses: ${unknown}`);
