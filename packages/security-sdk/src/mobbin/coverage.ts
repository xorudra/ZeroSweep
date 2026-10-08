import {
  BINARY_COVERAGE_DIMENSIONS, MOBILE_COVERAGE_DIMENSIONS,
  type BinaryCoverageDimension, type CoverageDimensionResult, type MobbinCoverageResult,
  type MobileCoverageDimension, type ProtectionEvidence,
} from "./types";

/**
 * Prompt 35 §121–§126 — coverage honesty for mobile & binary.
 *
 * Coverage is computed from what the analysis actually recorded —
 * never from what was requested. An unexamined dimension is
 * NOT_COVERED with a reason; any gap makes the completion
 * COMPLETED_WITH_GAPS (§124). Obfuscation (§125) and packing (§126)
 * evidence is detected from bounded signals; when symbols are
 * stripped or code is obfuscated, CODE_RULES/FUNCTIONS coverage is
 * capped and the snapshot says so — the platform never claims full
 * code coverage it does not have, and never unpacks protected
 * third-party software.
 */

export interface MobileCoverageInput {
  hasManifest: boolean;
  permissionCount: number;
  componentCount: number;
  codeRuleFindingCount: number;
  hasDecompiledEvidence: boolean;
  componentInventoryCount: number; // SBOM components
  secretScanRan: boolean;
  nativeLibraryCount: number;
  dynamicModulesRun: string[];
  trafficSessionCount: number;
  symbolsAvailable: boolean;
  obfuscation: ProtectionEvidence;
  packing: ProtectionEvidence;
}

function dim(status: CoverageDimensionResult["status"], detail: string): CoverageDimensionResult {
  return { status, detail };
}

export function computeMobileCoverage(input: MobileCoverageInput): MobbinCoverageResult<MobileCoverageDimension> & { obfuscation: ProtectionEvidence; packing: ProtectionEvidence } {
  const dimensions = {} as Record<MobileCoverageDimension, CoverageDimensionResult>;
  dimensions.MANIFEST = input.hasManifest ? dim("COVERED", "manifest/plist analyzed") : dim("NOT_COVERED", "no manifest/plist evidence recorded for this build");
  dimensions.PERMISSIONS = input.hasManifest ? dim("COVERED", `${input.permissionCount} permissions classified`) : dim("NOT_COVERED", "permissions derive from the manifest, which is absent");
  dimensions.COMPONENTS = input.componentCount > 0 ? dim("COVERED", `${input.componentCount} components inventoried`) : dim("NOT_COVERED", "no components inventoried");
  dimensions.CODE_RULES = !input.hasDecompiledEvidence
    ? dim("NOT_COVERED", "no decompiled/code evidence recorded — code rules did not run")
    : input.symbolsAvailable
      ? dim("COVERED", `${input.codeRuleFindingCount} code-rule observations`)
      : dim("NOT_COVERED", "symbols unavailable (stripped/obfuscated) — full code coverage is NOT claimed (§125)");
  dimensions.DEPENDENCIES = input.componentInventoryCount > 0 ? dim("COVERED", `${input.componentInventoryCount} SBOM components correlated`) : dim("NOT_COVERED", "no SBOM component inventory for this build");
  dimensions.SECRETS = input.secretScanRan ? dim("COVERED", "secret analysis ran (fingerprint + redacted preview only, §31)") : dim("NOT_COVERED", "secret analysis did not run");
  dimensions.NATIVE_LIBRARIES = input.nativeLibraryCount > 0 ? dim("COVERED", `${input.nativeLibraryCount} native libraries inventoried`) : dim("NOT_APPLICABLE", "no native libraries present in this build");
  dimensions.DYNAMIC_MODULES = input.dynamicModulesRun.length > 0 ? dim("COVERED", `dynamic modules run: ${input.dynamicModulesRun.join(", ")}`) : dim("NOT_COVERED", "no dynamic session ran — static-only coverage (§16)");
  dimensions.TRAFFIC = input.trafficSessionCount > 0 ? dim("COVERED", `${input.trafficSessionCount} governed traffic sessions`) : dim("NOT_COVERED", "no governed traffic capture for this build");
  const gaps = MOBILE_COVERAGE_DIMENSIONS.some((d) => dimensions[d].status === "NOT_COVERED");
  return { dimensions, completion: gaps ? "COMPLETED_WITH_GAPS" : "COMPLETED", obfuscation: input.obfuscation, packing: input.packing };
}

export interface BinaryCoverageInput {
  formatParsed: boolean;
  hasHardeningProfile: boolean;
  importCount: number;
  exportCount: number;
  stringCount: number;
  functionCount: number;
  dependencyCount: number;
  decompilationAvailable: boolean;
  decompilationUnavailableReason?: string;
}

export function computeBinaryCoverage(input: BinaryCoverageInput): MobbinCoverageResult<BinaryCoverageDimension> {
  const dimensions = {} as Record<BinaryCoverageDimension, CoverageDimensionResult>;
  dimensions.FORMAT_PARSING = input.formatParsed ? dim("COVERED", "format/architecture parsed by safe parser (§53)") : dim("NOT_COVERED", "format could not be parsed");
  dimensions.HARDENING = input.hasHardeningProfile ? dim("COVERED", "hardening profile recorded (checksec-class evidence, §54)") : dim("NOT_COVERED", "no hardening profile recorded");
  dimensions.IMPORTS_EXPORTS = input.importCount + input.exportCount > 0 ? dim("COVERED", `${input.importCount} imports / ${input.exportCount} exports (bounded, §56)`) : dim("NOT_COVERED", "no import/export inventory recorded");
  dimensions.STRINGS = input.stringCount > 0 ? dim("COVERED", `${input.stringCount} bounded strings extracted (§57/§58)`) : dim("NOT_COVERED", "no strings extracted");
  dimensions.FUNCTIONS = input.functionCount > 0 ? dim("COVERED", `${input.functionCount} functions inventoried`) : dim("NOT_COVERED", "no function inventory — symbols may be stripped (§125)");
  dimensions.DEPENDENCY_ANALYSIS = input.dependencyCount > 0 ? dim("COVERED", `${input.dependencyCount} dependencies correlated`) : dim("NOT_COVERED", "no dependency inventory recorded");
  dimensions.DECOMPILATION = input.decompilationAvailable
    ? dim("COVERED", "decompilation evidence available from a governed adapter")
    : dim("NOT_COVERED", input.decompilationUnavailableReason ?? "decompilation capability unavailable (licensed tool not installed, §64) — pipeline continues");
  const gaps = BINARY_COVERAGE_DIMENSIONS.some((d) => dimensions[d].status === "NOT_COVERED");
  return { dimensions, completion: gaps ? "COMPLETED_WITH_GAPS" : "COMPLETED" };
}

/** §125/§126: bounded protection-evidence detection from inventory
 *  signals. Records evidence + confidence only — never unpacks. */
export function detectProtectionEvidence(input: {
  stripped?: boolean;
  symbolCount?: number;
  functionCount?: number;
  highEntropySection?: boolean;
  knownPackerSignature?: string | null;
  obfuscatedNameRatio?: number; // 0..1 of single-letter/mangled names
}): { obfuscation: ProtectionEvidence; packing: ProtectionEvidence } {
  const obfSignals: string[] = [];
  if (input.obfuscatedNameRatio !== undefined && input.obfuscatedNameRatio > 0.6) obfSignals.push(`obfuscated-name ratio ${(input.obfuscatedNameRatio * 100).toFixed(0)}%`);
  if (input.stripped) obfSignals.push("symbols stripped");
  const packingSignals: string[] = [];
  if (input.highEntropySection) packingSignals.push("high-entropy section present");
  if (input.knownPackerSignature) packingSignals.push(`packer signature: ${input.knownPackerSignature}`);
  const conf = (n: number) => (n >= 2 ? "HIGH" : n === 1 ? "MEDIUM" : "NONE") as ProtectionEvidence["confidence"];
  return {
    obfuscation: { detected: obfSignals.length > 0, confidence: conf(obfSignals.length), signals: obfSignals },
    packing: { detected: packingSignals.length > 0, confidence: conf(packingSignals.length), signals: packingSignals },
  };
}
