/**
 * Prompt 18 — binary platform analysis (§20–§62): turns header
 * reports + extracted strings + tool inventories into the normalized
 * payload and findings, merges multi-tool observations into ONE
 * canonical finding (§58–§60), computes cross-build diffs with
 * security regressions (§53–§55) and crash fingerprints/triage
 * (§75–§77).
 *
 * Evidence discipline throughout:
 *  - An imported risky API is an OBSERVATION, not a vulnerability
 *    (§48): a finding requires call/reference evidence.
 *  - A version is never inferred from absent evidence (§25): soname
 *    majors are NOT versions; only full embedded versions correlate.
 *  - Strings that LOOK cryptographic are inventory (§46); only
 *    evidence-backed weak-crypto rules produce findings (§47).
 *  - Reachability (§62) is evidence state, never exploitability.
 */
import { createHash } from "node:crypto";
import type {
  NormalizedBinaryData, NormalizedBinaryDependency, NormalizedFinding,
  NormalizedSoftwareComponent,
} from "../findings/finding.types";
import type { BinaryHeaderReport } from "./detect";
import { buildHardeningProfile } from "./hardening";
import type { ExtractedStrings } from "./strings";

export function binarySha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** §57: cross-build fingerprint — lineage + function/component + rule
 *  + CWE + normalized location. Absolute addresses are EXCLUDED by
 *  construction (normalizedLocation is a name, never 0x…). */
export function binaryFindingFingerprint(input: {
  lineage: string; component: string; ruleId: string; cwe?: string;
  findingClass: string; location: string;
}): string {
  const loc = input.location.replace(/0x[0-9a-f]+/gi, "ADDR").replace(/\d+/g, "N");
  return `bin:${binarySha256Hex([input.lineage, input.component, input.ruleId, input.cwe ?? "", input.findingClass, loc].join("|")).slice(0, 32)}`;
}

/** §48: dangerous-API rules. Import alone = observation (metric);
 *  import + a function that references it = evidence-backed finding. */
export const RISKY_API_RULES: { api: string; ruleId: string; cwe: string; severity: "HIGH" | "MEDIUM"; note: string }[] = [
  { api: "gets", ruleId: "BINARY_RISKY_GETS", cwe: "CWE-242", severity: "HIGH", note: "gets() has no bounds checking and cannot be used safely" },
  { api: "strcpy", ruleId: "BINARY_RISKY_STRCPY", cwe: "CWE-120", severity: "MEDIUM", note: "strcpy() copies without a destination bound" },
  { api: "strcat", ruleId: "BINARY_RISKY_STRCAT", cwe: "CWE-120", severity: "MEDIUM", note: "strcat() appends without a destination bound" },
  { api: "sprintf", ruleId: "BINARY_RISKY_SPRINTF", cwe: "CWE-120", severity: "MEDIUM", note: "sprintf() formats without a destination bound" },
  { api: "alloca", ruleId: "BINARY_RISKY_ALLOCA", cwe: "CWE-770", severity: "MEDIUM", note: "alloca() allocates on the stack without failure handling" },
  { api: "system", ruleId: "BINARY_RISKY_SYSTEM", cwe: "CWE-78", severity: "HIGH", note: "system() executes a shell command string" },
  { api: "popen", ruleId: "BINARY_RISKY_POPEN", cwe: "CWE-78", severity: "HIGH", note: "popen() executes a shell command string" },
  { api: "scanf", ruleId: "BINARY_RISKY_SCANF", cwe: "CWE-120", severity: "MEDIUM", note: "scanf() without field widths can overflow destinations" },
];

/** §46/§47: weak-crypto evidence rules — algorithm named in a crypto
 *  context (import/library) produces an evidence-backed finding;
 *  a string that merely mentions it does not. */
const WEAK_CRYPTO = [
  { match: /(?:^|_)MD5(?:_|$)/i, name: "MD5", cwe: "CWE-327" },
  { match: /(?:^|_)SHA-?1(?:_|$)/i, name: "SHA-1", cwe: "CWE-327" },
  { match: /(?:^|_)(?:DES|3DES|RC4)(?:_|$)/i, name: "DES/3DES/RC4", cwe: "CWE-327" },
  { match: /_ECB_/i, name: "ECB mode", cwe: "CWE-327" },
];

const SONAME_VERSION_RE = /\.so\.(\d+\.\d+\.\d+)$/;
const LIB_BASE_RE = /^(?:lib)?([a-z0-9._+-]+?)(?:\.so|\.dll|\.dylib)/i;

export function dependencyFromLibraryName(name: string, source: string, sourceKind: NormalizedBinaryDependency["sourceKind"]): NormalizedBinaryDependency {
  const versionMatch = name.match(SONAME_VERSION_RE);
  const version = versionMatch?.[1];
  const base = name.match(LIB_BASE_RE)?.[1] ?? name;
  return {
    library: base,
    ...(version ? { version } : {}),
    ...(version ? { purl: `pkg:generic/${base}@${version}` } : {}),
    sourceKind,
    confidence: sourceKind === "DETECTED_LINKED" ? 0.8 : 0.6,
    source,
  };
}

export interface BinaryPlatformAnalysisInput {
  artifactName: string;
  sha256: string;
  sha1?: string;
  sizeBytes: number;
  report: BinaryHeaderReport;
  strings: ExtractedStrings;
  environment: string;
  source?: string; // platform analyzer slug
}

/** The §22–§50 platform analysis over one artifact's parsed headers +
 *  strings. Pure — no execution anywhere in this pipeline (§8/§100). */
export function analyzeBinaryPlatform(input: BinaryPlatformAnalysisInput): { data: NormalizedBinaryData; findings: NormalizedFinding[]; components: NormalizedSoftwareComponent[] } {
  const source = input.source ?? "binary-platform-analysis";
  const { report, strings } = input;
  const findings: NormalizedFinding[] = [];
  const lineage = `${report.format}:${report.architecture ?? "unknown"}:${input.artifactName}`;

  // Hardening profile + findings (§16/§17).
  const hardening = buildHardeningProfile(report, source);
  findings.push(...hardening.findings);

  // Sections (§14) + executable+writable anomaly (§45).
  const sections = report.sections.map((s) => ({ name: s.name, ...(s.type ? { type: s.type } : {}), offset: s.offset, size: s.size, virtualAddress: s.virtualAddress, permissions: s.permissions, ...(s.entropy !== undefined ? { entropy: s.entropy } : {}), source }));
  for (const s of report.sections) {
    if (s.permissions.includes("W") && s.permissions.includes("X")) {
      findings.push({
        title: `Writable + executable section: ${s.name}`,
        description: `Section ${s.name} of this ${report.format} artifact is both writable and executable (W+X). W+X memory undermines NX/DEP (§45).`,
        severity: "MEDIUM", confidence: 0.9, cwe: "CWE-693",
        references: [], sourceTool: source, sourceFingerprint: `binary:wx-section:${s.name}`, ruleId: "BINARY_WX_SECTION",
        binaryFindingType: "BINARY_CONFIGURATION_FINDING", binaryComponent: s.name,
        binaryReachability: "UNKNOWN", staticConfidence: "HIGH",
        remediation: "Remove the W+X mapping: split data and code permissions.",
      });
    }
  }

  // Debug information shipped in a production artifact (§44).
  if (report.hasDebugInfo && (input.environment === "PRODUCTION" || input.environment === "RELEASE")) {
    findings.push({
      title: "Debug information shipped in production binary",
      description: "This production artifact retains debug sections/symbols, which ease reverse engineering and may expose developer paths or internal names (§44). Debug paths were sanitized before persistence.",
      severity: "LOW", confidence: 0.85, cwe: "CWE-215",
      references: [], sourceTool: source, sourceFingerprint: `binary:debug-info:${input.sha256.slice(0, 12)}`, ruleId: "BINARY_DEBUG_INFO",
      binaryFindingType: "BINARY_CONFIGURATION_FINDING", binaryComponent: "debug-info",
      binaryReachability: "UNKNOWN", staticConfidence: "HIGH",
      remediation: "Strip production binaries and keep debug symbols as separately protected artifacts.",
    });
  }

  // Imports/exports/symbols (§19/§23/§24).
  const imports = report.importedSymbols.map((i) => ({ library: i.library ?? "unknown", symbol: i.symbol, source }));
  const exportList = report.exportedSymbols.map((s) => ({ symbol: s, source }));
  const symbols = report.symbolNames.map((n) => ({ name: n, source }));

  // Dependencies (§25–§27): dynamically-linked libraries — versions
  // only from reliably embedded version suffixes.
  const dependencies = report.dynamicLibraries.map((lib) => dependencyFromLibraryName(lib, source, "DETECTED_LINKED"));

  // Risky APIs (§48): import alone → observation ONLY. The imported
  // set is computed here to make the discipline explicit: no finding
  // is created from it — findings require function reference evidence
  // (riskyApiFindings, fed by Ghidra/radare2 inventories).
  const importedNames = new Set(imports.map((i) => i.symbol.replace(/@.*$/, "")));
  void importedNames;

  // Secrets (§30): candidates surfaced by the string pass — metadata
  // only; the finding never contains the value.
  for (const s of strings.strings) {
    if (s.category !== "SECRET_CANDIDATE") continue;
    findings.push({
      title: `Possible embedded secret in binary (${s.secretType ?? "unknown type"})`,
      description: `Binary string analysis found a ${s.secretType ?? "secret-shaped"} candidate${s.location ? ` in ${s.location}` : ""}. The value is NEVER persisted: this record carries only the type, location and one-way fingerprint (§30). Verify, rotate if real, and move secrets out of shipped binaries.`,
      severity: "HIGH", confidence: 0.7, cwe: "CWE-798",
      references: [], sourceTool: source,
      sourceFingerprint: `binary:secret:${s.secretFingerprint ?? s.secretType ?? "candidate"}`,
      ruleId: "BINARY_EMBEDDED_SECRET",
      binaryFindingType: "BINARY_SECRET", binaryComponent: s.location ?? "strings",
      binaryReachability: "UNKNOWN", staticConfidence: "MEDIUM",
      evidence: `secret candidate fingerprint ${s.secretFingerprint ?? "n/a"}${s.redactedPreview ? `, preview ${s.redactedPreview}` : ""}`,
    });
  }

  // Crypto inventory (§46/§47): imported crypto APIs are inventory;
  // weak algorithms in imported symbols are evidence-backed findings.
  const cryptoReferences: NormalizedBinaryData["cryptoReferences"] = [];
  for (const imp of imports) {
    if (/^(EVP_|CRYPTO_|SHA|MD5|AES_|DES_|RC4)/.test(imp.symbol) || /crypto|ssl|crypt32|bcrypt/i.test(imp.library)) {
      cryptoReferences.push({ kind: "LIBRARY", name: imp.symbol, source });
    }
    for (const weak of WEAK_CRYPTO) {
      if (weak.match.test(imp.symbol)) {
        findings.push({
          title: `Weak cryptography referenced: ${weak.name} (${imp.symbol})`,
          description: `The artifact imports ${imp.symbol}, evidence of ${weak.name} usage — a broken/risky cryptographic algorithm (§47). String mentions alone never produce this finding; the evidence is the imported symbol.`,
          severity: "MEDIUM", confidence: 0.75, cwe: weak.cwe,
          references: [], sourceTool: source, sourceFingerprint: `binary:weak-crypto:${imp.symbol}`, ruleId: "BINARY_WEAK_CRYPTO",
          binaryFindingType: "BINARY_STATIC_CODE_FINDING", binaryComponent: imp.symbol,
          binaryReachability: "UNKNOWN", staticConfidence: "MEDIUM",
          remediation: "Migrate to SHA-256+/AES-GCM or ChaCha20-Poly1305 via a maintained crypto library.",
        });
        break;
      }
    }
  }

  // Components for the SCA/intel path (§26).
  const components: NormalizedSoftwareComponent[] = dependencies
    .filter((d) => d.version)
    .map((d) => ({
      name: d.library, version: d.version, ecosystem: "generic-binary",
      purl: d.purl ?? `pkg:generic/${d.library}@${d.version}`,
      sourceManifest: input.artifactName, scope: "UNKNOWN", dependencyScope: "RUNTIME", licenses: [],
    }));

  const data: NormalizedBinaryData = {
    artifactName: input.artifactName,
    sha256: input.sha256, ...(input.sha1 ? { sha1: input.sha1 } : {}), sizeBytes: input.sizeBytes,
    format: report.format, kind: report.kind,
    ...(report.architecture ? { architecture: report.architecture } : {}),
    ...(report.bitness ? { bitness: report.bitness } : {}),
    ...(report.endianness ? { endianness: report.endianness } : {}),
    ...(report.platform ? { platform: report.platform } : {}),
    ...(report.entryPoint ? { entryPoint: report.entryPoint } : {}),
    stripped: report.stripped, hasDebugInfo: report.hasDebugInfo,
    debugPaths: report.debugPaths, compilerHints: report.compilerHints.slice(0, 32),
    sections, hardening: hardening.profile, functions: [], imports, exports: exportList, symbols,
    dependencies, strings: strings.strings, stringsSummary: strings.summary,
    cryptoReferences, discoveredReferences: strings.discoveredReferences, source,
  };
  // Stamp every finding with artifact identity + cross-build fingerprint.
  for (const f of findings) {
    f.binaryArtifactHash = input.sha256;
    f.binaryFingerprint = binaryFindingFingerprint({
      lineage, component: f.binaryComponent ?? "artifact", ruleId: f.ruleId ?? "BINARY",
      ...(f.cwe ? { cwe: f.cwe } : {}), findingClass: f.binaryFindingType ?? "BINARY_STATIC_CODE_FINDING",
      location: f.binaryComponent ?? "artifact",
    });
  }
  return { data, findings, components };
}

/** §48: risky-API findings from a tool function inventory — the
 *  function→API reference IS the evidence the platform pass lacks. */
export function riskyApiFindings(data: NormalizedBinaryData, source: string): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const lineage = `${data.format}:${data.architecture ?? "unknown"}:${data.artifactName ?? "artifact"}`;
  for (const fn of data.functions) {
    for (const api of fn.referencesRiskyApi ?? []) {
      const rule = RISKY_API_RULES.find((r) => r.api === api);
      if (!rule) continue;
      findings.push({
        title: `Risky API ${api}() referenced by ${fn.name}`,
        description: `Static analysis reports function ${fn.name} calling imported ${api}() — ${rule.note} (§48). This is evidence of the call, NOT proof of exploitable overflow; reachability is POSSIBLY_REACHABLE because static call-graph evidence exists (§62).`,
        severity: rule.severity, confidence: fn.confidence,
        cwe: rule.cwe, references: [], sourceTool: source,
        sourceFingerprint: `binary:risky-api:${rule.ruleId}:${fn.name}`,
        ruleId: rule.ruleId,
        binaryFindingType: "BINARY_STATIC_CODE_FINDING", binaryComponent: fn.name,
        binaryReachability: "POSSIBLY_REACHABLE",
        staticConfidence: fn.confidence >= 0.8 ? "HIGH" : fn.confidence >= 0.5 ? "MEDIUM" : "LOW",
        binaryArtifactHash: data.sha256,
        binaryFingerprint: binaryFindingFingerprint({
          lineage, component: fn.name, ruleId: rule.ruleId, cwe: rule.cwe,
          findingClass: "BINARY_STATIC_CODE_FINDING", location: fn.name,
        }),
      });
    }
  }
  return findings;
}

// ── Multi-tool merge (§40/§58–§60) ─────────────────────────────────

export interface BinaryObservation {
  canonicalFingerprint: string;
  tool: string;
  sourceFingerprint?: string;
  confidence?: number;
  observedAtStage?: string;
}

export function mergeBinaryObservations(findings: NormalizedFinding[]): { findings: NormalizedFinding[]; observations: BinaryObservation[] } {
  const byKey = new Map<string, NormalizedFinding>();
  const observations: BinaryObservation[] = [];
  for (const f of findings) {
    const key = f.binaryFingerprint ?? f.sourceFingerprint;
    observations.push({
      canonicalFingerprint: key, tool: f.sourceTool,
      ...(f.sourceFingerprint ? { sourceFingerprint: f.sourceFingerprint } : {}),
      ...(typeof f.confidence === "number" ? { confidence: f.confidence } : {}),
    });
    const existing = byKey.get(key);
    if (!existing || (f.confidence ?? 0) > (existing.confidence ?? 0)) byKey.set(key, f);
  }
  return { findings: [...byKey.values()], observations };
}

// ── Cross-build diff (§53–§55) ─────────────────────────────────────

export interface BinaryDiffResult {
  functionsAdded: string[];
  functionsRemoved: string[];
  functionsChanged: string[];
  dependenciesAdded: NormalizedBinaryDependency[];
  dependenciesRemoved: NormalizedBinaryDependency[];
  dependenciesChanged: { library: string; from?: string; to?: string }[];
  hardeningChanges: { name: string; from: string; to: string; regression: boolean }[];
  regressions: { kind: "HARDENING_REMOVED" | "VULNERABLE_DEPENDENCY_INTRODUCED" | "FINDING_REAPPEARED"; detail: string }[];
  summary: Record<string, number>;
}

export function diffBinaryArtifacts(base: NormalizedBinaryData, target: NormalizedBinaryData, opts: {
  vulnerableDependency?: (dep: NormalizedBinaryDependency) => boolean;
  resolvedFindingFingerprints?: Set<string>;
  targetFindingFingerprints?: Set<string>;
} = {}): BinaryDiffResult {
  const baseFns = new Map(base.functions.map((f) => [f.name, f.fingerprint ?? ""]));
  const targetFns = new Map(target.functions.map((f) => [f.name, f.fingerprint ?? ""]));
  const functionsAdded = [...targetFns.keys()].filter((n) => !baseFns.has(n));
  const functionsRemoved = [...baseFns.keys()].filter((n) => !targetFns.has(n));
  const functionsChanged = [...targetFns.keys()].filter((n) => baseFns.has(n) && baseFns.get(n) !== targetFns.get(n));

  const baseDeps = new Map(base.dependencies.map((d) => [d.library, d]));
  const targetDeps = new Map(target.dependencies.map((d) => [d.library, d]));
  const dependenciesAdded = [...targetDeps.values()].filter((d) => !baseDeps.has(d.library));
  const dependenciesRemoved = [...baseDeps.values()].filter((d) => !targetDeps.has(d.library));
  const dependenciesChanged = [...targetDeps.values()]
    .filter((d) => baseDeps.has(d.library) && baseDeps.get(d.library)?.version !== d.version)
    .map((d) => ({ library: d.library, ...(baseDeps.get(d.library)?.version ? { from: baseDeps.get(d.library)!.version } : {}), ...(d.version ? { to: d.version } : {}) }));

  const baseHard = new Map(base.hardening.map((h) => [h.name, h.status]));
  const regressions: BinaryDiffResult["regressions"] = [];
  const hardeningChanges: BinaryDiffResult["hardeningChanges"] = [];
  for (const h of target.hardening) {
    const from = baseHard.get(h.name);
    if (from && from !== h.status) {
      const regression = (from === "ENABLED" && h.status !== "ENABLED") || (from === "PARTIAL" && h.status === "DISABLED");
      hardeningChanges.push({ name: h.name, from, to: h.status, regression });
      if (regression) regressions.push({ kind: "HARDENING_REMOVED", detail: `${h.name}: ${from} → ${h.status}` });
    }
  }
  for (const dep of dependenciesAdded) {
    if (opts.vulnerableDependency?.(dep)) {
      regressions.push({ kind: "VULNERABLE_DEPENDENCY_INTRODUCED", detail: `${dep.library}${dep.version ? `@${dep.version}` : ""} introduced and matches the local vulnerability dataset` });
    }
  }
  if (opts.resolvedFindingFingerprints && opts.targetFindingFingerprints) {
    for (const fp of opts.targetFindingFingerprints) {
      if (opts.resolvedFindingFingerprints.has(fp)) {
        regressions.push({ kind: "FINDING_REAPPEARED", detail: `Previously resolved finding ${fp} is present again` });
      }
    }
  }
  return {
    functionsAdded, functionsRemoved, functionsChanged,
    dependenciesAdded, dependenciesRemoved, dependenciesChanged,
    hardeningChanges, regressions,
    summary: {
      functionsAdded: functionsAdded.length, functionsRemoved: functionsRemoved.length,
      functionsChanged: functionsChanged.length, dependenciesAdded: dependenciesAdded.length,
      dependenciesRemoved: dependenciesRemoved.length, regressions: regressions.length,
    },
  };
}

// ── Crash triage (§75–§77) ──────────────────────────────────────────

export interface BinaryCrashInput {
  signal: string;
  exceptionType?: string;
  faultingFunction?: string;
  stackFunctions: string[];
  /** Normalized register summary — metadata only, bounded (§74). */
  registerSummary?: Record<string, string>;
  artifactLineage: string;
  faultLooksLikeCanaryFailure?: boolean;
  faultingFunctionReferencesRiskyApi?: boolean;
}

export interface BinaryCrashTriage {
  fingerprint: string;
  classification: "LIKELY_SECURITY_RELEVANT" | "NEEDS_REVIEW" | "LIKELY_NON_SECURITY" | "UNKNOWN";
  reasons: string[];
}

/** §76/§77: dedup fingerprint from exception type + NORMALIZED stack
 *  (function names, never raw addresses) + faulting function +
 *  lineage. Triage is conservative: it NEVER claims exploitability. */
export function triageBinaryCrash(input: BinaryCrashInput): BinaryCrashTriage {
  const normalizedStack = input.stackFunctions.map((f) => f.replace(/0x[0-9a-f]+/gi, "ADDR")).slice(0, 16);
  const fingerprint = `crash:${binarySha256Hex([input.signal, input.exceptionType ?? "", input.faultingFunction ?? "", normalizedStack.join(">"), input.artifactLineage].join("|")).slice(0, 32)}`;
  const reasons: string[] = [];
  let classification: BinaryCrashTriage["classification"] = "NEEDS_REVIEW";
  if (input.faultLooksLikeCanaryFailure) {
    classification = "LIKELY_SECURITY_RELEVANT";
    reasons.push("Stack canary failure (__stack_chk_fail) indicates stack memory corruption reached the canary");
  } else if (input.faultingFunctionReferencesRiskyApi) {
    classification = "LIKELY_SECURITY_RELEVANT";
    reasons.push("Faulting function references a known risky API — memory-safety review warranted");
  } else if (/segv|sigsegv/i.test(input.signal) && /read|load/i.test(input.exceptionType ?? "") && !input.faultingFunction) {
    classification = "LIKELY_NON_SECURITY";
    reasons.push("Read fault with no identified faulting function and no risky-API evidence — likely an ordinary defect; still tracked, never weaponized (§77)");
  } else if (!input.signal) {
    classification = "UNKNOWN";
    reasons.push("No signal recorded — classification UNKNOWN, never guessed");
  } else {
    reasons.push("Crash captured and fingerprinted; classification requires analyst review — exploitability is NEVER claimed automatically (§77)");
  }
  return { fingerprint, classification, reasons };
}
