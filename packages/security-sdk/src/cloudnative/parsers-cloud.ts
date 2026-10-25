/**
 * Prompt 13 — cloud-native tool output parsers (§13–§47, §57–§60).
 *
 * Every parser consumes RECORDED tool output (fixtures in tests; tool
 * artifacts in production) and produces normalized records. Parsers
 * never invent data: fixed versions, CVSS and base images appear only
 * when the tool itself reported them (§23/§24). Secrets pass through
 * the Prompt 12 discipline — metadata + fingerprint + redacted preview,
 * the value itself is dropped at parse time (§18/§101).
 */
import type {
  NormalizedControlAssessment, NormalizedFinding, NormalizedKubernetesWorkload,
  NormalizedRuntimeEvent, NormalizedSoftwareComponent, NormalizedSbom,
} from "../findings/finding.types";
import type { Severity } from "@zerosweep/types";
import { buildPurl } from "../code/components";
import { SecretFingerprintService, classifySecretType, redactedPreview } from "../code/secrets";
import {
  configurationFingerprint, dockerBenchmarkFingerprint, imageSecretFingerprint,
  imageVulnerabilityFingerprint, kubernetesBenchmarkFingerprint,
} from "./correlation";
import { normalizeBaseImage, parseImageReference } from "./image";
import { sanitizeCloudText, sanitizeStringMap } from "./sanitize";
import type { NormalizedContainerImage } from "./types";

export interface CloudParserContext {
  toolSlug: string;
  /** Image identity the output belongs to (digest = strongest, §5). */
  imageRef?: string;
  imageDigest?: string;
  /** Cluster / host subject references for posture outputs. */
  clusterRef?: string;
  hostRef?: string;
  /** Trivy scanner kinds for this run (§15) — parsers honor them exactly. */
  scanKinds?: string[];
  /** Origin stamped on findings (§51). */
  origin?: NormalizedFinding["origin"];
  fingerprinter?: SecretFingerprintService;
}

export interface ParsedCloud {
  findings: NormalizedFinding[];
  components: NormalizedSoftwareComponent[];
  images: NormalizedContainerImage[];
  workloads: NormalizedKubernetesWorkload[];
  controlAssessments: NormalizedControlAssessment[];
  runtimeEvents: NormalizedRuntimeEvent[];
  sbom?: NormalizedSbom;
  metrics: Record<string, number>;
}

export function emptyParsedCloud(metrics: Record<string, number> = {}): ParsedCloud {
  return { findings: [], components: [], images: [], workloads: [], controlAssessments: [], runtimeEvents: [], metrics };
}

function sev(raw: unknown, fallback: Severity = "MEDIUM"): Severity {
  const s = String(raw ?? "").toUpperCase();
  if (s === "CRITICAL") return "CRITICAL";
  if (s === "HIGH") return "HIGH";
  if (s === "MEDIUM" || s === "MODERATE") return "MEDIUM";
  if (s === "LOW") return "LOW";
  if (s === "NONE" || s === "NEGLIGIBLE" || s === "UNKNOWN") return "INFORMATIONAL";
  return fallback;
}

function parseJson(text: string): Record<string, unknown> {
  const parsed = JSON.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("tool output is not a JSON object");
  return parsed as Record<string, unknown>;
}

function arr(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.filter((x): x is Record<string, unknown> => !!x && typeof x === "object") : [];
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/** Package origin (§21): Trivy Class/Type and Grype artifact types tell
 *  OS packages apart from language-ecosystem packages. */
function packageTypeOf(cls: string | undefined, type: string | undefined): "OS" | "LANGUAGE" | "UNKNOWN" {
  const c = (cls ?? "").toLowerCase();
  if (c.includes("os-pkgs") || c === "os") return "OS";
  if (c.includes("lang-pkgs") || c === "language") return "LANGUAGE";
  const t = (type ?? "").toLowerCase();
  if (["alpine", "debian", "ubuntu", "redhat", "wolfi", "chainguard", "os"].includes(t)) return "OS";
  if (t) return "LANGUAGE";
  return "UNKNOWN";
}

function ecosystemOf(type: string | undefined): string {
  const t = (type ?? "").toLowerCase();
  const map: Record<string, string> = {
    npm: "npm", node: "npm", yarn: "npm", pnpm: "npm", python: "pypi", pip: "pypi", gem: "rubygems",
    ruby: "rubygems", maven: "maven", gradle: "maven", go: "golang", "go-module": "golang",
    cargo: "cargo", rust: "cargo", composer: "composer", php: "composer", nuget: "nuget", apk: "apk",
    deb: "deb", rpm: "rpm", alpine: "apk", debian: "deb", ubuntu: "deb", redhat: "rpm",
  };
  return map[t] ?? (t || "unknown");
}

// ── Trivy (§13–§18) ──────────────────────────────────────────────────

/**
 * Trivy JSON. Vulnerabilities, misconfigurations and secrets are
 * DIFFERENT result kinds and stay separate (§16): misconfigurations map
 * to compliance controls and never borrow CVE identity; secrets become
 * metadata-only secret findings (§18). The image record is emitted
 * when Metadata is present (config analyzed statically, §9).
 */
export function parseTrivy(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const fingerprinter = ctx.fingerprinter ?? new SecretFingerprintService();
  const imageRef = ctx.imageRef ?? str(root.ArtifactName) ?? "unknown-image";
  const imageDigest = ctx.imageDigest;
  const metadata = (root.Metadata ?? {}) as Record<string, unknown>;
  const imageId = str(metadata.ImageID);
  const digest = imageDigest ?? (imageId?.startsWith("sha256:") ? imageId : undefined);
  const osInfo = (metadata.OS ?? {}) as Record<string, unknown>;
  const config = (metadata.Config ?? {}) as Record<string, unknown>;
  const layers = arr(metadata.Layers ?? (root as Record<string, unknown>).LayerDiffIDs).map(() => ({}));
  void layers;
  const diffIds = Array.isArray(metadata.DiffIDs) ? (metadata.DiffIDs as unknown[]).filter((d): d is string => typeof d === "string") : [];
  if (root.ArtifactType === "container_image" || metadata.ImageID || root.ArtifactName) {
    out.images.push({
      reference: imageRef,
      registry: safeRegistryOf(imageRef), repository: safeRepositoryOf(imageRef),
      ...(tagOf(imageRef) ? { tag: tagOf(imageRef) } : {}),
      ...(digest ? { digest } : {}),
      ...(str(osInfo.Name) ? { os: str(osInfo.Name) } : {}),
      source: ctx.toolSlug,
      config: {
        ...(str(config.User) ? { user: str(config.User) } : {}),
        exposedPorts: Object.keys((config.ExposedPorts ?? {}) as Record<string, unknown>),
        entrypointPresent: Array.isArray(config.Entrypoint) && (config.Entrypoint as unknown[]).length > 0,
        cmdPresent: Array.isArray(config.Cmd) && (config.Cmd as unknown[]).length > 0,
        envKeys: (Array.isArray(config.Env) ? (config.Env as unknown[]) : []).map((e) => String(e).split("=")[0]!).filter(Boolean).slice(0, 100),
        labels: sanitizeStringMap(config.Labels),
      },
      layers: diffIds.map((d) => ({ digest: d })),
    });
  }
  let secretFindingsDisabled = 0;
  // Scanner kinds are honored exactly (§15): a config-only run must
  // never surface CVE or secret findings and vice versa.
  const kinds = new Set(ctx.scanKinds ?? ["vuln", "config", "secret"]);
  for (const result of arr(root.Results)) {
    const target = str(result.Target) ?? imageRef;
    const cls = str(result.Class);
    const type = str(result.Type);
    const pkgType = packageTypeOf(cls, type);
    for (const vuln of kinds.has("vuln") ? arr(result.Vulnerabilities) : []) {
      const cve = str(vuln.VulnerabilityID);
      const pkg = str(vuln.PkgName) ?? "unknown-package";
      const version = str(vuln.InstalledVersion) ?? "";
      if (!cve) continue;
      const purl = buildPurl(ecosystemOf(type), pkg, version || undefined);
      out.findings.push({
        title: `${cve} in ${pkg} ${version}`.trim(),
        description: sanitizeCloudText(vuln.Description ?? vuln.Title ?? `${cve} affecting ${pkg}`, 2000),
        severity: sev(vuln.Severity),
        confidence: 0.9,
        cve,
        ...(str(vuln.CweIDs ? (vuln.CweIDs as string[])[0] : undefined) ? { cwe: str(vuln.CweIDs ? (vuln.CweIDs as string[])[0] : undefined) } : {}),
        ...(num(vuln.CVSS ? ((vuln.CVSS as Record<string, unknown>).nvd as Record<string, unknown> | undefined)?.V3Score : undefined) ? { cvssScore: num(((vuln.CVSS as Record<string, unknown>).nvd as Record<string, unknown>).V3Score) } : {}),
        references: Array.isArray(vuln.References) ? (vuln.References as unknown[]).filter((r): r is string => typeof r === "string").slice(0, 10) : [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: imageVulnerabilityFingerprint({ imageDigest: digest, imageRef, cve, packageName: pkg, packageVersion: version }),
        origin: "IMAGE_FINDING",
        ...(digest ? { imageDigest: digest } : {}),
        imageRef,
        componentName: pkg,
        ...(version ? { componentVersion: version } : {}),
        componentPurl: purl,
        // Fixed versions appear ONLY when Trivy reports them (§24).
        ...(str(vuln.FixedVersion) ? { fixedVersion: str(vuln.FixedVersion) } : {}),
        packageType: pkgType,
        ...(str(vuln.Layer ? ((vuln.Layer as Record<string, unknown>).DiffID as string | undefined) : undefined) ? { layerDigest: str((vuln.Layer as Record<string, unknown>).DiffID) } : {}),
        evidence: sanitizeCloudText(`Trivy matched ${pkg} ${version} in ${target} against ${cve} (package type: ${pkgType}).`, 1000),
        remediation: str(vuln.FixedVersion)
          ? `Update ${pkg} to ${str(vuln.FixedVersion)} or later, or move to a base image that carries the fix.`
          : `No fixed version is published for ${cve} in ${pkg} per the scanner data; track the advisory and reduce exposure meanwhile.`,
      });
    }
    for (const mis of kinds.has("config") ? arr(result.Misconfigurations) : []) {
      const checkId = str(mis.AVDID) ?? str(mis.ID) ?? "TRIVY-CONFIG";
      const causeMeta = (mis.CauseMetadata ?? {}) as Record<string, unknown>;
      const resource = str(causeMeta.Resource) ?? target;
      const [resourceKind, resourceName] = resource.includes("/") ? resource.split("/", 2) : [undefined, resource];
      out.findings.push({
        title: sanitizeCloudText(mis.Title ?? `Misconfiguration ${checkId}`, 300),
        description: sanitizeCloudText(mis.Description ?? "", 2000),
        severity: sev(mis.Severity),
        confidence: 0.85,
        references: str(mis.Resolution) || str(mis.PrimaryURL) ? [str(mis.PrimaryURL) ?? ""].filter(Boolean) : [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: `trivyconfig:${checkId}:${target}`.toLowerCase(),
        origin: "STATIC_CONFIGURATION_FINDING",
        ruleId: checkId,
        controlId: checkId,
        ...(resourceKind ? { resourceKind } : {}),
        ...(resourceName ? { resourceName } : {}),
        ...(str(causeMeta.Namespace) ? { namespace: str(causeMeta.Namespace) } : {}),
        filePath: target.includes("/") || target.includes(".") ? target : undefined,
        ...(num(causeMeta.StartLine) ? { startLine: num(causeMeta.StartLine) } : {}),
        evidence: sanitizeCloudText(`Trivy config check ${checkId} failed for ${resource}.`, 1000),
        ...(str(mis.Resolution) ? { remediation: str(mis.Resolution) } : {}),
      });
      out.controlAssessments.push({
        frameworkKey: "CIS_KUBERNETES", controlId: checkId, subjectRef: target,
        status: "FAIL", evidence: sanitizeCloudText(mis.Title ?? checkId, 300),
      });
    }
    for (const secret of kinds.has("secret") ? arr(result.Secrets) : []) {
      // §18: the Match text (which CONTAINS the value) is used only to
      // fingerprint, in-memory; it is never copied into any record.
      const match = str(secret.Match) ?? "";
      const ruleId = str(secret.RuleID) ?? "trivy-secret";
      if (!match) { secretFindingsDisabled++; continue; }
      const fingerprint = fingerprinter.fingerprint(match);
      out.findings.push({
        title: `Secret detected in image (${classifySecretType("trivy", ruleId)})`,
        description: "A secret was detected in the image filesystem/history by Trivy. The value is never stored; rotate the credential and rebuild the image without it.",
        severity: "HIGH",
        confidence: 0.8,
        references: [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: imageSecretFingerprint({ imageDigest: digest, imageRef, secretType: classifySecretType("trivy", ruleId), location: target }),
        origin: "IMAGE_FINDING",
        ...(digest ? { imageDigest: digest } : {}),
        imageRef,
        ruleId,
        secret: {
          secretType: classifySecretType("trivy", ruleId),
          detector: ruleId,
          fingerprint,
          ...(redactedPreview(match) ? { redactedPreview: redactedPreview(match) } : {}),
          verificationStatus: "NOT_VERIFIED",
        },
        evidence: `Secret metadata only: type=${classifySecretType("trivy", ruleId)} detector=${ruleId} location=${target}`,
      });
    }
  }
  out.metrics = {
    imageVulnerabilities: out.findings.filter((f) => f.origin === "IMAGE_FINDING" && !f.secret).length,
    misconfigurations: out.controlAssessments.length,
    secretFindings: out.findings.filter((f) => f.secret).length,
    // Secret hits whose matched text was empty cannot be fingerprinted
    // and are counted, never stored (§18).
    secretsSkippedNoMatch: secretFindingsDisabled,
  };
  return out;
}

function safeRegistryOf(ref: string): string {
  try { return parseImageReference(ref).registry; } catch { return "unknown"; }
}
function safeRepositoryOf(ref: string): string {
  try { return parseImageReference(ref).repository; } catch { return sanitizeCloudText(ref, 300); }
}
function tagOf(ref: string): string | undefined {
  try { return parseImageReference(ref).tag; } catch { return undefined; }
}

// ── Grype (image / SBOM inputs, §19) ─────────────────────────────────

interface GrypeMatch { vulnId: string; pkg: string; version: string; fix?: string; severity: string; purl: string; pkgType: "OS" | "LANGUAGE" | "UNKNOWN"; layerDigest?: string; locations: string[] }

/** Shared Grype match extraction — used by the source Grype parser
 *  (code/parsers-code) AND the image parser below so the two input
 *  kinds can never drift apart (§19: one adapter, two input kinds). */
export function extractGrypeMatches(root: Record<string, unknown>): GrypeMatch[] {
  const matches: GrypeMatch[] = [];
  for (const m of arr(root.matches)) {
    const vuln = (m.vulnerability ?? {}) as Record<string, unknown>;
    const artifact = (m.artifact ?? {}) as Record<string, unknown>;
    const id = str(vuln.id);
    const pkg = str(artifact.name);
    if (!id || !pkg) continue;
    const version = str(artifact.version) ?? "";
    const fixVersions = arr(vuln.fix ? ((vuln.fix as Record<string, unknown>).versions as unknown[] ?? []) : []).map(String);
    void fixVersions;
    const fixRaw = (vuln.fix as Record<string, unknown> | undefined)?.versions;
    const fix = Array.isArray(fixRaw) && typeof fixRaw[0] === "string" ? fixRaw[0] : undefined;
    const locations = arr(artifact.locations).map((l) => str(l.path) ?? "").filter(Boolean);
    const layerDigest = arr(artifact.locations).map((l) => str((l.layerID as string | undefined) ?? str((l as Record<string, unknown>).layerId))).find(Boolean);
    matches.push({
      vulnId: id, pkg, version,
      ...(fix ? { fix } : {}),
      severity: str(vuln.severity) ?? "Unknown",
      purl: str(artifact.purl) ?? buildPurl(ecosystemOf(str(artifact.type)), pkg, version || undefined),
      pkgType: packageTypeOf(undefined, str(artifact.type)),
      ...(layerDigest ? { layerDigest } : {}),
      locations,
    });
  }
  return matches;
}

/** Grype over a container image or an SBOM (§19): findings bind to the
 *  image digest and share the §20 fingerprint with Trivy. */
export function parseGrypeImage(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const imageRef = ctx.imageRef ?? "unknown-image";
  const descriptor = (root.descriptor ?? {}) as Record<string, unknown>;
  const source = (root.source ?? {}) as Record<string, unknown>;
  const sourceMeta = (source.metadata ?? {}) as Record<string, unknown>;
  const digest = ctx.imageDigest ?? str(sourceMeta.manifestDigest) ?? str(descriptor.id);
  for (const match of extractGrypeMatches(root)) {
    out.findings.push({
      title: `${match.vulnId} in ${match.pkg} ${match.version}`.trim(),
      description: sanitizeCloudText(`Grype matched ${match.pkg} ${match.version} against ${match.vulnId}.`, 2000),
      severity: sev(match.severity),
      confidence: 0.9,
      cve: match.vulnId.startsWith("CVE-") ? match.vulnId : undefined,
      references: [],
      sourceTool: ctx.toolSlug,
      sourceFingerprint: imageVulnerabilityFingerprint({ imageDigest: digest, imageRef, cve: match.vulnId, packageName: match.pkg, packageVersion: match.version }),
      origin: "IMAGE_FINDING",
      ...(digest ? { imageDigest: digest } : {}),
      imageRef,
      componentName: match.pkg,
      ...(match.version ? { componentVersion: match.version } : {}),
      componentPurl: match.purl,
      ...(match.fix ? { fixedVersion: match.fix } : {}),
      packageType: match.pkgType,
      ...(match.layerDigest ? { layerDigest: match.layerDigest } : {}),
      evidence: sanitizeCloudText(`Grype matched ${match.pkg} ${match.version} at ${match.locations[0] ?? "image"} (package type: ${match.pkgType}).`, 1000),
    });
  }
  out.metrics = { imageVulnerabilities: out.findings.length };
  return out;
}

// ── Syft (§12–§14) ───────────────────────────────────────────────────

/** Syft JSON → package inventory. Artifacts become the SAME component
 *  records the source pipeline uses (§14), so image SBOMs feed the
 *  existing SBOM models. CycloneDX input is handled by
 *  parseCycloneDxComponents below. */
export function parseSyft(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const source = (root.source ?? {}) as Record<string, unknown>;
  const meta = (source.metadata ?? {}) as Record<string, unknown>;
  const imageRef = ctx.imageRef ?? str(meta.userInput) ?? "unknown-image";
  const digest = ctx.imageDigest ?? str(meta.manifestDigest) ?? (str(meta.imageID)?.startsWith("sha256:") ? str(meta.imageID) : undefined);
  for (const artifact of arr(root.artifacts)) {
    const name = str(artifact.name);
    if (!name) continue;
    const version = str(artifact.version);
    const type = str(artifact.type);
    out.components.push({
      name,
      ...(version ? { version } : {}),
      ecosystem: ecosystemOf(type),
      purl: str(artifact.purl) ?? buildPurl(ecosystemOf(type), name, version),
      sourceManifest: "syft-image-inventory",
      scope: "UNKNOWN",
      dependencyScope: "RUNTIME",
      licenses: Array.isArray(artifact.licenses) ? (artifact.licenses as unknown[]).filter((l): l is string => typeof l === "string") : [],
    });
    if (out.components.length >= 20000) break;
  }
  if (source.type === "image" || meta.userInput) {
    out.images.push({
      reference: imageRef,
      registry: safeRegistryOf(imageRef), repository: safeRepositoryOf(imageRef),
      ...(tagOf(imageRef) ? { tag: tagOf(imageRef) } : {}),
      ...(digest ? { digest } : {}),
      ...(str(meta.architecture) ? { architecture: str(meta.architecture) } : {}),
      ...(str(meta.os) ? { os: str(meta.os) } : {}),
      source: ctx.toolSlug,
      layers: arr(meta.layers).map((l) => ({ digest: str(l.digest) ?? "", ...(num(l.size) ? { sizeBytes: num(l.size) } : {}) })).filter((l) => l.digest),
    });
  }
  out.metrics = { packages: out.components.length };
  return out;
}

/** CycloneDX document → components (§14). Used for Syft CycloneDX
 *  output and imported image SBOMs; components keep PURL identity. */
export function parseCycloneDxComponents(text: string): NormalizedSoftwareComponent[] {
  const root = parseJson(text);
  if (root.bomFormat !== "CycloneDX") throw new Error("not a CycloneDX document");
  const components: NormalizedSoftwareComponent[] = [];
  for (const c of arr(root.components)) {
    const name = str(c.name);
    if (!name) continue;
    const purl = str(c.purl) ?? buildPurl(ecosystemOf(str(c.type)), name, str(c.version));
    components.push({
      name,
      ...(str(c.version) ? { version: str(c.version) } : {}),
      ecosystem: ecosystemOf(str(c.type)),
      purl,
      sourceManifest: "cyclonedx-sbom",
      scope: "UNKNOWN",
      dependencyScope: "RUNTIME",
      licenses: arr(c.licenses).map((l) => str((l.license as Record<string, unknown> | undefined)?.id) ?? str((l.license as Record<string, unknown> | undefined)?.name)).filter((x): x is string => !!x),
    });
  }
  const meta = (root.metadata ?? {}) as Record<string, unknown>;
  const comp = (meta.component ?? {}) as Record<string, unknown>;
  void comp;
  return components;
}

/** The image record embedded in a CycloneDX SBOM's metadata (§14). */
export function cycloneDxImage(text: string): NormalizedContainerImage | undefined {
  const root = parseJson(text);
  const meta = (root.metadata ?? {}) as Record<string, unknown>;
  const comp = (meta.component ?? {}) as Record<string, unknown>;
  const name = str(comp.name);
  if (!name || str(comp.type) !== "container") return undefined;
  const hashes = arr(comp.hashes);
  const digestHash = hashes.find((h) => str(h.alg)?.includes("SHA-256"));
  const digest = digestHash ? `sha256:${str(digestHash.content) ?? ""}` : undefined;
  return {
    registry: safeRegistryOf(name), repository: safeRepositoryOf(name),
    ...(tagOf(name) ? { tag: tagOf(name) } : {}),
    ...(digest && digest.length === 71 ? { digest } : {}),
    source: "SBOM",
  };
}

// ── Docker Bench (§28–§31) ───────────────────────────────────────────

/** docker-bench-for-security JSON → CIS Docker control assessments.
 *  WARN results are the tool's failures and become findings; PASS is
 *  posture evidence only (§31/§56). */
export function parseDockerBench(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const hostRef = ctx.hostRef ?? "docker-host";
  for (const test of arr(root.tests)) {
    const id = str(test.id) ?? "";
    const result = str(test.result) ?? "INFO";
    const desc = sanitizeCloudText(test.desc ?? id, 500);
    const status = result === "PASS" ? "PASS" : result === "WARN" ? "FAIL" : result === "INFO" || result === "NOTE" ? "UNKNOWN" : "UNKNOWN";
    out.controlAssessments.push({
      frameworkKey: "CIS_DOCKER", controlId: id, subjectRef: hostRef,
      status, evidence: desc,
    });
    if (status === "FAIL") {
      out.findings.push({
        title: `Docker CIS ${id}: ${desc}`,
        description: sanitizeCloudText(test.details ?? desc, 2000),
        severity: "MEDIUM",
        confidence: 0.9,
        references: [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: dockerBenchmarkFingerprint({ hostRef, checkId: id }),
        origin: "DOCKER_HOST_FINDING",
        ruleId: id,
        controlId: id,
        evidence: sanitizeCloudText(test.details ?? desc, 1000),
        ...(str(test.remediation) ? { remediation: sanitizeCloudText(test.remediation, 1000) } : {}),
      });
    }
  }
  out.metrics = { checks: out.controlAssessments.length, failedChecks: out.findings.length };
  return out;
}

// ── kube-bench (§39–§41) ─────────────────────────────────────────────

/** kube-bench JSON → CIS Kubernetes control assessments + findings for
 *  FAIL results (§40/§41). Runs only on approved hosts via the
 *  dedicated privileged worker — the parser doesn't care, the executor
 *  gate does (§39). */
export function parseKubeBench(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const clusterRef = ctx.clusterRef ?? "kubernetes-cluster";
  for (const control of arr(root.Controls)) {
    for (const test of arr(control.tests)) {
      for (const result of arr(test.results)) {
        const id = str(result.test_number) ?? str(test.section) ?? "";
        const statusRaw = (str(result.status) ?? "INFO").toUpperCase();
        const status = statusRaw === "PASS" ? "PASS" : statusRaw === "FAIL" ? "FAIL" : statusRaw === "WARN" ? "WARN" : "UNKNOWN";
        const desc = sanitizeCloudText(result.test_desc ?? result.test_info ?? id, 500);
        out.controlAssessments.push({
          frameworkKey: "CIS_KUBERNETES", controlId: id, subjectRef: clusterRef,
          status, evidence: desc,
        });
        if (status === "FAIL") {
          out.findings.push({
            title: `Kubernetes CIS ${id}: ${desc}`,
            description: sanitizeCloudText(result.test_info ?? desc, 2000),
            severity: "HIGH",
            confidence: 0.9,
            references: [],
            sourceTool: ctx.toolSlug,
            sourceFingerprint: kubernetesBenchmarkFingerprint({ clusterRef, checkId: id }),
            origin: "LIVE_CLUSTER_FINDING",
            clusterRef,
            ruleId: id,
            controlId: id,
            evidence: sanitizeCloudText(result.test_info ?? desc, 1000),
            ...(str(result.remediation) ? { remediation: sanitizeCloudText(result.remediation, 1000) } : {}),
          });
        }
      }
    }
  }
  out.metrics = { checks: out.controlAssessments.length, failedChecks: out.findings.length };
  return out;
}

// ── Kubescape (§44/§45) ──────────────────────────────────────────────

/** Kubescape JSON (v2/v3 resource results). Failed controls become
 *  configuration findings bound to the resource identity (§54);
 *  origin is LIVE for cluster scans, STATIC for manifest scans (the
 *  adapter sets it). Duplicate controls across frameworks dedupe via
 *  the shared fingerprint (§45). */
export function parseKubescape(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const origin = ctx.origin ?? "LIVE_CLUSTER_FINDING";
  const seen = new Set<string>();
  for (const result of arr(root.results)) {
    const resource = (result.resource ?? result.resourceID ?? {}) as Record<string, unknown>;
    const source = (resource.source as Record<string, unknown> | undefined) ?? {};
    const kind = str(resource.kind) ?? str(source.kind) ?? "Workload";
    const namespace = str(resource.namespace) ?? str(source.namespace) ?? "default";
    const name = str(resource.name) ?? str(source.name) ?? "unknown";
    for (const control of arr(result.controls)) {
      const controlId = str(control.controlID) ?? str(control.id) ?? "";
      const statusObj = (control.status as Record<string, unknown> | undefined) ?? {};
      const status = (str(control.status) ?? str(statusObj.status) ?? "").toLowerCase();
      const failed = status === "failed" || arr(control.rules).some((r) => (str((r.status as Record<string, unknown> | undefined)?.status) ?? str(r.status)) === "failed");
      if (!failed || !controlId) continue;
      const containers = arr(control.rules).flatMap((r) => arr((r as Record<string, unknown>).failedResources)).map(() => "");
      void containers;
      const fingerprint = configurationFingerprint({ namespace, resourceKind: kind, resourceName: name, controlId });
      if (seen.has(fingerprint)) continue; // §45 duplicate config findings collapse
      seen.add(fingerprint);
      out.findings.push({
        title: sanitizeCloudText(str(control.name) ?? `Kubescape control ${controlId}`, 300),
        description: sanitizeCloudText(str(control.name) ?? "", 2000),
        severity: sev(str(control.severity) ?? (control as Record<string, unknown>).baseScore ? "HIGH" : "MEDIUM"),
        confidence: 0.85,
        references: str(control.remediation) ? [] : [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: fingerprint,
        origin,
        ...(ctx.clusterRef ? { clusterRef: ctx.clusterRef } : {}),
        namespace, resourceKind: kind, resourceName: name,
        ruleId: controlId, controlId,
        evidence: sanitizeCloudText(`Kubescape control ${controlId} failed for ${kind} ${namespace}/${name}.`, 1000),
        ...(str(control.remediation) ? { remediation: sanitizeCloudText(control.remediation, 1000) } : {}),
      });
      out.controlAssessments.push({
        frameworkKey: "NSA_CISA_KUBERNETES", controlId, subjectRef: `${kind} ${namespace}/${name}`,
        status: "FAIL", evidence: sanitizeCloudText(str(control.name) ?? controlId, 300),
      });
    }
  }
  out.metrics = { failedControls: out.findings.length };
  return out;
}

// ── kube-hunter (§42/§43) ────────────────────────────────────────────

/** kube-hunter JSON. Only checks the policy allowed reach this parser
 *  in automated runs (the adapter refuses intrusive modes); results are
 *  exposure findings bound to the cluster (§43). */
export function parseKubeHunter(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const root = parseJson(text);
  const clusterRef = ctx.clusterRef ?? "kubernetes-cluster";
  for (const vuln of arr(root.vulnerabilities)) {
    const name = str(vuln.vulnerability) ?? str(vuln.category) ?? "kube-hunter finding";
    const location = str(vuln.location) ?? clusterRef;
    out.findings.push({
      title: sanitizeCloudText(name, 300),
      description: sanitizeCloudText(vuln.description ?? "", 2000),
      severity: sev(vuln.severity),
      confidence: 0.7,
      references: [],
      sourceTool: ctx.toolSlug,
      sourceFingerprint: `kubehunter:${clusterRef}:${str(vuln.category) ?? "misc"}:${name}`.toLowerCase().replace(/\s+/g, "-"),
      origin: "LIVE_CLUSTER_FINDING",
      clusterRef,
      ruleId: str(vuln.category),
      evidence: sanitizeCloudText(`kube-hunter observed ${name} at ${location}: ${str(vuln.evidence) ?? ""}`, 1000),
    });
  }
  out.metrics = { services: arr(root.services).length, vulnerabilities: out.findings.length };
  return out;
}

// ── Checkov (§46/§47) ────────────────────────────────────────────────

/** Checkov JSON (single report object or array). Failed checks become
 *  STATIC configuration findings with repository-relative file paths
 *  and line ranges; passed checks are counted, never faked into
 *  findings (§47). IaC/Helm/Kubernetes/Dockerfile share this parser. */
export function parseCheckov(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const parsed = JSON.parse(text) as unknown;
  const reports = Array.isArray(parsed) ? parsed.filter((r): r is Record<string, unknown> => !!r && typeof r === "object") : [parseJson(text)];
  let passed = 0;
  for (const report of reports) {
    const results = (report.results ?? {}) as Record<string, unknown>;
    passed += arr(results.passed_checks).length;
    for (const check of arr(results.failed_checks)) {
      const checkId = str(check.check_id) ?? "CKV_UNKNOWN";
      const filePath = (str(check.file_path) ?? str(check.file_abs_path) ?? "unknown").replace(/^\//, "");
      const resource = str(check.resource) ?? filePath;
      const lineRange = Array.isArray(check.file_line_range) ? (check.file_line_range as number[]) : [];
      // Kubernetes resources carry kind/namespace/name identity (§54).
      const kindMatch = resource.match(/^([A-Za-z]+)\.([^.]+)\.(.+)$/);
      // Prompt 14 §62: Terraform addresses (aws_s3_bucket.name /
      // module.aws_s3_bucket.name) carry the deployed resource NAME in
      // the trailing segment — the identity IaC/live correlation uses.
      const tfMatch = !kindMatch ? resource.match(/^[a-z][a-z0-9_]*\.(.+)$/) : null;
      const tfName = tfMatch ? tfMatch[1]!.split(".").pop() : undefined;
      out.findings.push({
        title: sanitizeCloudText(str(check.check_name) ?? `Checkov ${checkId}`, 300),
        description: sanitizeCloudText(str(check.check_name) ?? "", 2000),
        severity: sev(str(check.severity), "MEDIUM"),
        confidence: 0.85,
        references: str(check.guideline) ? [str(check.guideline)!] : [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: `checkov:${checkId}:${filePath}:${resource}`.toLowerCase(),
        origin: "STATIC_CONFIGURATION_FINDING",
        ruleId: checkId,
        controlId: checkId,
        filePath,
        ...(typeof lineRange[0] === "number" ? { startLine: lineRange[0] } : {}),
        ...(typeof lineRange[1] === "number" ? { endLine: lineRange[1] } : {}),
        ...(kindMatch ? { resourceKind: kindMatch[1], namespace: kindMatch[2], resourceName: kindMatch[3] } : {}),
        ...(!kindMatch && tfName ? { resourceName: tfName } : {}),
        evidence: sanitizeCloudText(`Checkov ${checkId} failed for ${resource} in ${filePath}.`, 1000),
        ...(str(check.guideline) ? { remediation: `Follow the Checkov guidance for ${checkId}: ${str(check.guideline)}` } : {}),
      });
    }
  }
  out.metrics = { failedChecks: out.findings.length, passedChecks: passed };
  return out;
}

// ── Falco (§57–§60) ─────────────────────────────────────────────────

/**
 * Falco JSONL → runtime events. Every field is sanitized (§60):
 * control characters stripped, secrets redacted, lengths capped —
 * event output is a stored-XSS / log-injection vector and is treated
 * as hostile text, never trusted markup.
 */
export function parseFalcoEvents(text: string, ctx: CloudParserContext): ParsedCloud {
  const out = emptyParsedCloud();
  const lines = text.split("\n").filter((l) => l.trim().length > 0).slice(0, 10000);
  for (const line of lines) {
    let raw: Record<string, unknown>;
    try { raw = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
    const fields = (raw.output_fields ?? {}) as Record<string, unknown>;
    const event: NormalizedRuntimeEvent = {
      rule: sanitizeCloudText(raw.rule ?? "unknown-rule", 300),
      priority: (str(raw.priority) ?? "NOTICE").toUpperCase(),
      eventTime: str(raw.time) ?? new Date(0).toISOString(),
      metadata: sanitizeStringMap(fields, { maxEntries: 40, maxValue: 300 }),
      source: ctx.toolSlug,
      ...(str(fields["k8s.ns.name"]) ?? str(fields["namespace"]) ? { namespace: sanitizeCloudText(str(fields["k8s.ns.name"]) ?? str(fields["namespace"]), 200) } : {}),
      ...(str(fields["k8s.pod.name"]) ?? str(fields["pod"]) ? { pod: sanitizeCloudText(str(fields["k8s.pod.name"]) ?? str(fields["pod"]), 200) } : {}),
      ...(str(fields["container.name"]) ? { container: sanitizeCloudText(str(fields["container.name"]), 200) } : {}),
      ...(str(fields["node"]) ?? str(raw.hostname) ? { node: sanitizeCloudText(str(fields["node"]) ?? str(raw.hostname), 200) } : {}),
      ...(ctx.clusterRef ? { clusterName: ctx.clusterRef } : {}),
    };
    // The human-readable output string is sanitized like any other
    // hostile field before it can be kept (§60).
    if (str(raw.output)) event.metadata.output = sanitizeCloudText(raw.output, 500);
    out.runtimeEvents.push(event);
  }
  out.metrics = { runtimeEvents: out.runtimeEvents.length };
  return out;
}

export { normalizeBaseImage };
