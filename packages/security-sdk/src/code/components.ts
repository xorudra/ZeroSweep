import { createHash } from "node:crypto";
import type { NormalizedSbom, NormalizedSoftwareComponent } from "../findings/finding.types";

/**
 * Dependency inventory (Prompt 12 §45–§57). Components are identified
 * from MANIFESTS and LOCKFILES — lockfiles first (§56) because they pin
 * the exact resolved graph. The platform NEVER installs packages (§57):
 * manifests are read as data. Every component carries its PURL (§46),
 * which is the identity SCA correlation and SBOM generation build on.
 */

type Component = NormalizedSoftwareComponent;

function depScope(raw: string | undefined, fallback: Component["dependencyScope"] = "RUNTIME"): Component["dependencyScope"] {
  const v = (raw ?? "").toLowerCase();
  if (["dev", "development", "devdependencies"].includes(v)) return "DEVELOPMENT";
  if (v === "test") return "TEST";
  if (v === "provided") return "PROVIDED";
  if (v === "runtime" || v === "compile" || v === "dependencies") return "RUNTIME";
  return fallback;
}

/** Build a Package URL (§46) per the purl-spec for supported ecosystems. */
export function buildPurl(ecosystem: string, name: string, version?: string, qualifiers?: Record<string, string>): string {
  let n = name;
  if (ecosystem === "npm") {
    // Per the purl-spec canonical form, a scope's "@" is percent-encoded
    // while the scope/name slash is kept: pkg:npm/%40angular/core@1.0.0.
    n = name.startsWith("@") ? "%40" + name.slice(1) : name;
  } else if (ecosystem === "pypi") {
    n = name.toLowerCase().replace(/[-_.]+/g, "-");
  } else if (ecosystem === "golang") {
    n = name.split("/").map((seg) => (/[A-Z]/.test(seg) ? seg.split("").map((c) => (/[A-Z]/.test(c) ? "!" + c.toLowerCase() : c)).join("") : seg)).join("/");
  }
  const base = `pkg:${ecosystem}/${n}${version ? `@${encodeURIComponent(version)}` : ""}`;
  const qs = qualifiers && Object.keys(qualifiers).length > 0
    ? "?" + Object.entries(qualifiers).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&")
    : "";
  return base + qs;
}

function component(ecosystem: string, name: string, version: string | undefined, sourceManifest: string, scope: Component["scope"], dependencyScope: Component["dependencyScope"], licenses: string[] = []): Component {
  let purl: string;
  if (ecosystem === "maven") {
    const [group, artifact] = name.split(":");
    purl = buildPurl("maven", `${group}/${artifact}`, version);
    return { name, version, ecosystem, purl, sourceManifest, scope, dependencyScope, licenses };
  }
  purl = buildPurl(ecosystem, name, version);
  return { name, version, ecosystem, purl, sourceManifest, scope, dependencyScope, licenses };
}

// ── npm: package.json + package-lock.json (lockfile first, §56) ──────

function parsePackageJson(content: string, path: string): Component[] {
  let json: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try { json = JSON.parse(content); } catch { return []; }
  const out: Component[] = [];
  for (const [name, range] of Object.entries(json.dependencies ?? {})) {
    out.push(component("npm", name, range.replace(/^[\^~>=<\s]*/, "") || undefined, path, "DIRECT", "RUNTIME"));
  }
  for (const [name, range] of Object.entries(json.devDependencies ?? {})) {
    out.push(component("npm", name, range.replace(/^[\^~>=<\s]*/, "") || undefined, path, "DIRECT", "DEVELOPMENT"));
  }
  return out;
}

function parsePackageLock(content: string, path: string): Component[] {
  let json: { packages?: Record<string, { version?: string; dev?: boolean }>; dependencies?: Record<string, { version?: string; dev?: boolean }> };
  try { json = JSON.parse(content); } catch { return []; }
  const out: Component[] = [];
  if (json.packages) {
    for (const [key, info] of Object.entries(json.packages)) {
      if (!key.startsWith("node_modules/") || !info.version) continue;
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      const direct = !key.slice(0, key.lastIndexOf("node_modules/")).includes("node_modules/");
      out.push(component("npm", name, info.version, path, direct ? "DIRECT" : "TRANSITIVE", info.dev ? "DEVELOPMENT" : "RUNTIME"));
    }
  } else if (json.dependencies) {
    for (const [name, info] of Object.entries(json.dependencies)) {
      if (info.version) out.push(component("npm", name, info.version, path, "DIRECT", info.dev ? "DEVELOPMENT" : "RUNTIME"));
    }
  }
  return out;
}

/** pnpm-lock.yaml — tolerant line parser over the packages/snapshots keys. */
function parsePnpmLock(content: string, path: string): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  for (const line of content.split(/\r?\n/)) {
    const m = /^\s{2}\/?((?:@[^/]+\/)?[^@/:\s]+)@(\d[^:\s]*)/.exec(line) ?? /^\s{2}((?:@[^/]+\/)?[^@/:\s]+)@(\d[^:\s]*):/.exec(line);
    if (m) {
      const key = `${m[1]}@${m[2]}`;
      if (!seen.has(key)) { seen.add(key); out.push(component("npm", m[1], m[2], path, "UNKNOWN", "RUNTIME")); }
    }
  }
  return out;
}

/** yarn.lock (classic) — `name@range:` headers with resolved versions. */
function parseYarnLock(content: string, path: string): Component[] {
  const out: Component[] = [];
  const blocks = content.split(/\n(?=\S)/);
  for (const block of blocks) {
    const header = /^((?:@[^/]+\/)?[^@\s"]+)@/.exec(block.trim());
    const version = /\n\s+version\s+"([^"]+)"/.exec(block);
    if (header && version) out.push(component("npm", header[1], version[1], path, "UNKNOWN", "RUNTIME"));
  }
  return out;
}

// ── Python ────────────────────────────────────────────────────────────

function parseRequirementsTxt(content: string, path: string): Component[] {
  const out: Component[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(?:==|>=|~=|<=|>|<)?\s*([A-Za-z0-9.*+!-]+)?/.exec(line);
    if (m) out.push(component("pypi", m[1], m[2] && !m[2].includes("*") ? m[2] : undefined, path, "DIRECT", "RUNTIME"));
  }
  return out;
}

function parsePipfileLock(content: string, path: string): Component[] {
  let json: { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
  try { json = JSON.parse(content); } catch { return []; }
  const out: Component[] = [];
  for (const [name, info] of Object.entries(json.default ?? {})) out.push(component("pypi", name, info.version?.replace(/^==/, ""), path, "DIRECT", "RUNTIME"));
  for (const [name, info] of Object.entries(json.develop ?? {})) out.push(component("pypi", name, info.version?.replace(/^==/, ""), path, "DIRECT", "DEVELOPMENT"));
  return out;
}

function parsePoetryLock(content: string, path: string): Component[] {
  const out: Component[] = [];
  for (const block of content.split(/^\[\[package\]\]/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const category = /^category\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name) out.push(component("pypi", name, version, path, "UNKNOWN", category === "dev" ? "DEVELOPMENT" : "RUNTIME"));
  }
  return out;
}

// ── JVM ───────────────────────────────────────────────────────────────

function parsePomXml(content: string, path: string): Component[] {
  const out: Component[] = [];
  const props = new Map<string, string>();
  for (const m of content.matchAll(/<([A-Za-z0-9_.-]+)>([^<]+)<\/\1>/g)) {
    if (m[1].endsWith(".version") || m[1] === "project.version") props.set(m[1], m[2].trim());
  }
  for (const block of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const body = block[1];
    const group = /<groupId>([^<]+)<\/groupId>/.exec(body)?.[1]?.trim();
    const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(body)?.[1]?.trim();
    let version = /<version>([^<]+)<\/version>/.exec(body)?.[1]?.trim();
    const scopeRaw = /<scope>([^<]+)<\/scope>/.exec(body)?.[1]?.trim();
    if (version?.startsWith("${")) version = props.get(version.slice(2, -1)) ?? undefined;
    if (group && artifact) out.push(component("maven", `${group}:${artifact}`, version, path, "DIRECT", depScope(scopeRaw, "RUNTIME")));
  }
  return out;
}

function parseGradle(content: string, path: string): Component[] {
  const out: Component[] = [];
  for (const m of content.matchAll(/(implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]/g)) {
    out.push(component("maven", `${m[2]}:${m[3]}`, m[4], path, "DIRECT", m[1].includes("test") ? "TEST" : m[1] === "compileOnly" ? "PROVIDED" : "RUNTIME"));
  }
  return out;
}

// ── Ruby / Go / Rust / PHP ────────────────────────────────────────────

function parseGemfileLock(content: string, path: string): Component[] {
  const out: Component[] = [];
  let inSpecs = false;
  for (const line of content.split(/\r?\n/)) {
    if (/^\s*specs:/.test(line)) { inSpecs = true; continue; }
    if (inSpecs) {
      const m = /^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)/.exec(line);
      if (m) out.push(component("gem", m[1], m[2], path, "UNKNOWN", "RUNTIME"));
      else if (/^\S/.test(line) || /^ {2}\S/.test(line)) inSpecs = false;
    }
  }
  return out;
}

function parseGoMod(content: string, path: string): Component[] {
  const out: Component[] = [];
  let inRequireBlock = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split("//")[0].trim();
    if (line === "require (") { inRequireBlock = true; continue; }
    if (inRequireBlock && line === ")") { inRequireBlock = false; continue; }
    const candidate = inRequireBlock ? line : line.replace(/^require\s+/, "");
    if (candidate !== line || inRequireBlock) {
      const m = /^(\S+)\s+v(\S+)$/.exec(candidate);
      if (m && m[1].includes(".")) out.push(component("golang", m[1], `v${m[2]}`, path, inRequireBlock ? "UNKNOWN" : "DIRECT", "RUNTIME"));
    }
  }
  return out;
}

function parseCargoLock(content: string, path: string): Component[] {
  const out: Component[] = [];
  for (const block of content.split(/^\[\[package\]\]/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name) out.push(component("cargo", name, version, path, "UNKNOWN", "RUNTIME"));
  }
  return out;
}

function parseComposerLock(content: string, path: string): Component[] {
  let json: { packages?: { name: string; version?: string }[]; "packages-dev"?: { name: string; version?: string }[] };
  try { json = JSON.parse(content); } catch { return []; }
  const out: Component[] = [];
  for (const p of json.packages ?? []) out.push(component("composer", p.name, p.version?.replace(/^v/, ""), path, "UNKNOWN", "RUNTIME"));
  for (const p of json["packages-dev"] ?? []) out.push(component("composer", p.name, p.version?.replace(/^v/, ""), path, "UNKNOWN", "DEVELOPMENT"));
  return out;
}

const MANIFEST_PARSERS: { match: (base: string) => boolean; parse: (content: string, path: string) => Component[] }[] = [
  { match: (b) => b === "package-lock.json", parse: parsePackageLock },
  { match: (b) => b === "package.json", parse: parsePackageJson },
  { match: (b) => b === "pnpm-lock.yaml", parse: parsePnpmLock },
  { match: (b) => b === "yarn.lock", parse: parseYarnLock },
  { match: (b) => b === "requirements.txt", parse: parseRequirementsTxt },
  { match: (b) => b === "pipfile.lock", parse: parsePipfileLock },
  { match: (b) => b === "poetry.lock", parse: parsePoetryLock },
  { match: (b) => b === "pom.xml", parse: parsePomXml },
  { match: (b) => b === "build.gradle" || b === "build.gradle.kts", parse: parseGradle },
  { match: (b) => b === "gemfile.lock", parse: parseGemfileLock },
  { match: (b) => b === "go.mod", parse: parseGoMod },
  { match: (b) => b === "cargo.lock", parse: parseCargoLock },
  { match: (b) => b === "composer.lock", parse: parseComposerLock },
];

/** True when a repository file is a parseable manifest/lockfile. */
export function isManifestPath(path: string): boolean {
  const base = (path.split("/").pop() ?? "").toLowerCase();
  return MANIFEST_PARSERS.some((p) => p.match(base));
}

/**
 * Parse every manifest/lockfile in the snapshot into the component
 * inventory (§45). Lockfiles win over manifests for the same ecosystem
 * (§56): when a lockfile exists for an ecosystem, manifest-only entries
 * for that ecosystem are dropped in favour of the resolved graph.
 */
export function parseManifests(manifestContents: Record<string, string>): Component[] {
  const byEcosystem = new Map<string, { lock: Component[]; manifest: Component[] }>();
  for (const [path, content] of Object.entries(manifestContents)) {
    const base = (path.split("/").pop() ?? "").toLowerCase();
    const parser = MANIFEST_PARSERS.find((p) => p.match(base));
    if (!parser) continue;
    const parsed = parser.parse(content, path);
    const isLock = /lock/.test(base);
    for (const c of parsed) {
      const bucket = byEcosystem.get(c.ecosystem) ?? { lock: [], manifest: [] };
      (isLock ? bucket.lock : bucket.manifest).push(c);
      byEcosystem.set(c.ecosystem, bucket);
    }
  }
  const merged: Component[] = [];
  for (const bucket of byEcosystem.values()) {
    merged.push(...(bucket.lock.length > 0 ? bucket.lock : bucket.manifest));
  }
  return dedupeComponents(merged);
}

/** Component identity = PURL (§45/§46); duplicates merge scope/licenses. */
export function dedupeComponents(components: Component[]): Component[] {
  const byPurl = new Map<string, Component>();
  for (const c of components) {
    const existing = byPurl.get(c.purl);
    if (!existing) { byPurl.set(c.purl, { ...c, licenses: [...c.licenses] }); continue; }
    if (existing.scope === "UNKNOWN" && c.scope !== "UNKNOWN") existing.scope = c.scope;
    if (existing.dependencyScope === "UNKNOWN") existing.dependencyScope = c.dependencyScope;
    existing.licenses = [...new Set([...existing.licenses, ...c.licenses])];
  }
  return [...byPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl));
}

/** Best-effort CPE 2.3 canonical string for intelligence lookup (§33):
 *  derived from the component identity only — never fabricated data. */
export function componentToCpe(component: Component): string | null {
  if (!component.version) return null;
  if (component.ecosystem === "maven") {
    const [group, artifact] = component.name.split(":");
    if (!group || !artifact) return null;
    return `cpe:2.3:a:${group}:${artifact}:${component.version}`;
  }
  if (["npm", "pypi", "gem", "cargo", "composer"].includes(component.ecosystem)) {
    const product = component.name.split("/").pop() ?? component.name;
    return `cpe:2.3:a:${component.ecosystem}:${product}:${component.version}`;
  }
  return null;
}

// ── SBOM generation (§47/§48) ─────────────────────────────────────────

export interface SbomMetadata {
  snapshotHash: string;
  repositoryName: string;
  timestamp: string;
}

/** CycloneDX 1.5 document for the inventory — checksummed, referenceable. */
export function buildCycloneDxSbom(components: Component[], meta: SbomMetadata): { document: string; sbom: NormalizedSbom } {
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${createHash("sha256").update(meta.snapshotHash).digest("hex").replace(/(.{8})(.{4})(.{4})(.{4})(.{12}).*/, "$1-$2-$3-$4-$5")}`,
    version: 1,
    metadata: {
      timestamp: meta.timestamp,
      component: { type: "application", name: meta.repositoryName, "bom-ref": `pkg:generic/${meta.repositoryName}@snapshot-${meta.snapshotHash.slice(0, 12)}` },
      tools: [{ vendor: "ZeroSweep", name: "ZeroSweep Source Code Security Engine", version: "1.0.0" }],
    },
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      ...(c.version ? { version: c.version } : {}),
      purl: c.purl,
      scope: c.dependencyScope === "DEVELOPMENT" || c.dependencyScope === "TEST" ? "optional" : "required",
      ...(c.licenses.length > 0 ? { licenses: c.licenses.map((id) => ({ license: { id } })) } : {}),
      properties: [
        { name: "dsrclone:source-manifest", value: c.sourceManifest },
        { name: "dsrclone:directness", value: c.scope },
      ],
    })),
  };
  const document = JSON.stringify(doc, null, 2);
  return {
    document,
    sbom: {
      format: "CYCLONEDX_JSON", specVersion: "1.5",
      checksum: createHash("sha256").update(document).digest("hex"),
      componentCount: components.length,
    },
  };
}

/** SPDX 2.3 tag-value document (§48) for the same inventory. */
export function buildSpdxSbom(components: Component[], meta: SbomMetadata): { document: string; sbom: NormalizedSbom } {
  const lines = [
    "SPDXVersion: SPDX-2.3",
    "DataLicense: CC0-1.0",
    `DocumentName: ${meta.repositoryName}-sbom`,
    `DocumentNamespace: https://dsrclone.local/sbom/${meta.snapshotHash}`,
    "Creator: Tool: ZeroSweep-1.0.0",
    `Created: ${meta.timestamp.replace(/\.\d+Z$/, "Z")}`,
    "",
  ];
  for (const c of components) {
    lines.push(
      `PackageName: ${c.name}`,
      ...(c.version ? [`PackageVersion: ${c.version}`] : []),
      "PackageSupplier: NOASSERTION",
      `PackageExternalRef: PACKAGE-MANAGER purl ${c.purl}`,
      `## source manifest: ${c.sourceManifest}`,
      "",
    );
  }
  const document = lines.join("\n");
  return {
    document,
    sbom: {
      format: "SPDX_TAG_VALUE", specVersion: "2.3",
      checksum: createHash("sha256").update(document).digest("hex"),
      componentCount: components.length,
    },
  };
}
