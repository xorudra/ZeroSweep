/**
 * Prompt 18 — binary adapters (§15/§18–§21/§33/§34).
 *
 *  - ChecksecAdapter: hardening properties of a registered artifact.
 *  - GhidraBinaryAdapter: REUSES AND EXTENDS the Prompt 17
 *    GhidraAdapter (same executable, same administrator-approved
 *    script directory, same headless governance) with the binary
 *    report schema (functions/imports/exports/strings/hardening).
 *    There is deliberately NO second independent Ghidra integration
 *    (§18). When the scan config carries a mobile build it delegates
 *    to the Prompt 17 behavior unchanged.
 *  - Radare2Adapter: typed analysis profiles ONLY. The command line
 *    is composed by the adapter from the approved operation set;
 *    config carrying commands/scripts is refused at validation
 *    (§34/§112).
 *
 * GDB/pwndbg have NO adapters here (§64–§68): they exist as governed
 * registrations + the debug policy (debug-policy.ts), and Cutter is
 * an ANALYST_TOOL descriptor (§35). IDA/Binary Ninja are connectors
 * (connectors.ts).
 */
import type { ToolMetadata } from "../adapter/adapter.types";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import { GhidraAdapter } from "../mobile/adapters-mobile";

/** The administrator-approved Ghidra scripts directory — the SAME
 *  governed directory the Prompt 17 adapter plans against (§18/§20).
 *  Binary mode adds ONE platform script from it; nothing else is
 *  expressible. */
export const GHIDRA_APPROVED_SCRIPTS_DIR = "/opt/zerosweep/ghidra-scripts";
import type { ParsedMobile } from "../mobile/types";
import { BinaryAdapterBase, assertBinaryConfig, binConfigStr } from "./binary-adapter.base";
import {
  RADARE2_OPERATIONS, parseBinaryGhidraReport, parseChecksecReport, parseRadare2Report,
  RADARE2_OPERATION_COMMANDS, type BinaryParserContext, type Radare2Operation,
} from "./parsers-binary";
import { emptyParsedBinary, type ParsedBinary } from "./types";

function binaryMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "BINARY",
    executionMode: "CONTAINER",
    riskLevel: "LOW",
    requiresApproval: false,
    supportedTargetTypes: ["BINARY"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 1200, maxTimeoutSeconds: 2400,
    resources: { cpu: "1", memory: "2Gi", timeoutSeconds: 1200 },
    requiredWorkerType: "BINARY_STATIC_ANALYSIS",
    ...partial,
  };
}

// ── checksec (§15) ──────────────────────────────────────────────────

export class ChecksecAdapter extends BinaryAdapterBase {
  readonly executable = "checksec";
  readonly containerImage = "zerosweep/checksec:local";
  readonly versionArgs = ["--version"];
  readonly metadata: ToolMetadata = binaryMeta({
    id: "adapter-checksec", slug: "checksec", name: "checksec",
    description: "checksec hardening analysis (Prompt 18 §15): NX/PIE/RELRO/canary/FORTIFY properties of a registered binary artifact, parsed from headers — the artifact is input data, never executed.",
    capabilities: ["BINARY_HARDENING_ANALYSIS"], licenseType: "OPEN_SOURCE",
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1200,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [
      { name: "binaryArtifactId", type: "string", description: "Registered BinaryArtifact id — worker-derived" },
      { name: "binaryArtifactHash", type: "string", description: "SHA-256 of the registered artifact — worker-derived" },
      { name: "binaryArtifactReference", type: "string", description: "Object-storage reference of the artifact — worker-derived" },
      { name: "binaryArtifactName", type: "string", description: "Artifact display name — worker-derived" },
      { name: "timeoutSeconds", type: "number", description: "Execution timeout override" },
    ],
  });

  protected parseBinary(text: string, ctx: BinaryParserContext): ParsedBinary {
    return parseChecksecReport(text, ctx);
  }

  protected binaryPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const ref = binConfigStr(config, "binaryArtifactReference") ?? binConfigStr(config, "binaryArtifactId");
    if (!ref) throw new AdapterConfigurationError("checksec plan requires a registered binary artifact reference (worker-derived, §6)");
    return { args: ["--format=json", `--file=${ref}`] };
  }
}

// ── Ghidra — reuse + extend the Prompt 17 adapter (§18) ────────────

export const GHIDRA_BINARY_APPROVED_SCRIPT = "BinarySecurityInventory.py" as const;

export class GhidraBinaryAdapter extends GhidraAdapter {
  override readonly metadata: ToolMetadata = binaryMeta({
    id: "adapter-ghidra", slug: "ghidra", name: "Ghidra", adapterVersion: "1.1.0",
    description: "Ghidra headless static analysis (Prompt 17 §34–§36, EXTENDED by Prompt 18 §18–§21): native-library hardening inventory PLUS the binary function/import/export/string inventory, from administrator-approved scripts only. Binaries are never executed; no arbitrary Ghidra script is expressible.",
    capabilities: ["BINARY_STATIC_ANALYSIS", "NATIVE_LIBRARY_ANALYSIS", "DISASSEMBLY", "DECOMPILATION", "FUNCTION_ANALYSIS", "IMPORT_EXPORT_ANALYSIS", "STRING_REFERENCE_ANALYSIS"],
    supportedTargetTypes: ["MOBILE_APP", "BINARY"], licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE", requiresApproval: true,
    defaultTimeoutSeconds: 1800, maxTimeoutSeconds: 3600,
    resources: { cpu: "4", memory: "8Gi", timeoutSeconds: 1800 },
    // Dual-mode (§18): the worker maps whichever family's keys the
    // scan context carries — binary keys select the binary plan,
    // mobile keys delegate to the Prompt 17 plan unchanged.
    inputSchema: [
      { name: "binaryArtifactId", type: "string", description: "Registered BinaryArtifact id — worker-derived" },
      { name: "binaryArtifactHash", type: "string", description: "SHA-256 of the registered artifact — worker-derived" },
      { name: "binaryArtifactReference", type: "string", description: "Object-storage reference of the artifact — worker-derived" },
      { name: "binaryArtifactName", type: "string", description: "Artifact display name — worker-derived" },
      { name: "mobileApplicationId", type: "string", description: "Registered MobileApplication id — worker-derived (Prompt 17 mode)" },
      { name: "mobileBuildId", type: "string", description: "Registered MobileBuild id — worker-derived (Prompt 17 mode)" },
      { name: "mobileBuildHash", type: "string", description: "SHA-256 build identity — worker-derived (Prompt 17 mode)" },
      { name: "mobileApplicationRef", type: "string", description: "Package name / bundle id — worker-derived (Prompt 17 mode)" },
      { name: "mobilePlatform", type: "string", description: "ANDROID | IOS — worker-derived (Prompt 17 mode)" },
      { name: "mobileArtifactReference", type: "string", description: "Object-storage reference of the app artifact — worker-derived (Prompt 17 mode)" },
      { name: "timeoutSeconds", type: "number", description: "Execution timeout override" },
    ],
  });

  private isBinaryMode(config: Record<string, unknown>): boolean {
    return typeof config.binaryArtifactReference === "string" || typeof config.binaryArtifactId === "string";
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    if (this.isBinaryMode(config)) assertBinaryConfig(config);
    await super.validateConfiguration(config);
  }

  protected override planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    if (!this.isBinaryMode(config)) return super.planFor(target, config);
    const ref = binConfigStr(config, "binaryArtifactReference") ?? binConfigStr(config, "binaryArtifactId");
    if (!ref) throw new AdapterConfigurationError("ghidra binary plan requires a registered binary artifact reference (worker-derived, §6)");
    // Same governed shape as Prompt 17: headless analyzer, project in
    // the sandbox workspace, ONE approved script pinned by the
    // platform from the SAME approved scripts directory — script
    // selection is never configuration (§20).
    return {
      args: [
        "BinarySandbox", "BinaryInventory",
        "-import", ref,
        "-scriptPath", GHIDRA_APPROVED_SCRIPTS_DIR,
        "-postScript", GHIDRA_BINARY_APPROVED_SCRIPT,
        "-deleteProject",
      ],
    };
  }

  override async parse(raw: string): Promise<ParsedBinary | ParsedMobile> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedBinary();
    if (this.isBinaryMode(this.lastConfig)) {
      const c = this.lastConfig;
      return parseBinaryGhidraReport(text, {
        toolSlug: "ghidra",
        ...(binConfigStr(c, "binaryArtifactId") ? { artifactId: binConfigStr(c, "binaryArtifactId")! } : {}),
        artifactHash: binConfigStr(c, "binaryArtifactHash") ?? "unknown-artifact",
        artifactName: binConfigStr(c, "binaryArtifactName") ?? "artifact",
      });
    }
    return super.parse(raw);
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    if (this.isBinaryMode(this.lastConfig)) {
      const p = parsed as ParsedBinary;
      return {
        assets: [], services: [], endpoints: [], technologies: [],
        findings: p.findings ?? [],
        ...(p.binary ? { binary: p.binary } : {}),
        artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
      };
    }
    return super.normalize(parsed);
  }
}

// ── radare2 (§33/§34) ───────────────────────────────────────────────

/** §33: a radare2 analysis profile — typed operations only. */
export interface Radare2AnalysisProfile {
  operations: Radare2Operation[];
  includeDisabledFunctions?: boolean;
}

export const RADARE2_PROFILES: Record<string, Radare2AnalysisProfile> = {
  QUICK: { operations: ["METADATA", "SECTIONS", "IMPORTS"] },
  STANDARD: { operations: ["METADATA", "SECTIONS", "IMPORTS", "EXPORTS", "FUNCTIONS", "SYMBOLS"] },
  FULL: { operations: ["METADATA", "SECTIONS", "IMPORTS", "EXPORTS", "FUNCTIONS", "STRINGS", "SYMBOLS"] },
};

export class Radare2Adapter extends BinaryAdapterBase {
  readonly executable = "r2";
  readonly containerImage = "zerosweep/radare2:local";
  readonly versionArgs = ["-v"];
  readonly metadata: ToolMetadata = binaryMeta({
    id: "adapter-radare2", slug: "radare2", name: "radare2",
    description: "Radare2 static binary analysis (Prompt 18 §33/§34): typed analysis profiles ONLY — the command line is composed by the adapter from the approved operation set; unrestricted r2 commands via the API are rejected and never planned.",
    capabilities: ["STATIC_BINARY_ANALYSIS", "DISASSEMBLY", "FUNCTION_INVENTORY", "IMPORT_EXPORT_ANALYSIS", "STRING_ANALYSIS"],
    licenseType: "OPEN_SOURCE", riskLevel: "MODERATE",
    resources: { cpu: "2", memory: "4Gi", timeoutSeconds: 1200 },
    inputSchema: [
      { name: "binaryArtifactId", type: "string", description: "Registered BinaryArtifact id — worker-derived" },
      { name: "binaryArtifactHash", type: "string", description: "SHA-256 of the registered artifact — worker-derived" },
      { name: "binaryArtifactReference", type: "string", description: "Object-storage reference of the artifact — worker-derived" },
      { name: "binaryArtifactName", type: "string", description: "Artifact display name — worker-derived" },
      { name: "binaryAnalysisProfile", type: "string", description: "Approved radare2 analysis profile name (§33)" },
      { name: "binaryOperations", type: "string[]", description: "Typed radare2 operations (§34) — commands are never accepted" },
      { name: "timeoutSeconds", type: "number", description: "Execution timeout override" },
    ],
  });

  /** Compose the analysis batch from TYPED operations only (§34). */
  static composeCommand(operations: Radare2Operation[]): string {
    const parts = operations.map((op) => {
      const cmd = RADARE2_OPERATION_COMMANDS[op];
      if (!cmd) throw new AdapterConfigurationError(`radare2 operation "${op}" is not an approved typed operation (§34)`);
      return cmd;
    });
    // -2: no stderr scripts, -q: quit after commands, -- : artifact is data.
    return parts.join(";");
  }

  protected parseBinary(text: string, ctx: BinaryParserContext): ParsedBinary {
    return parseRadare2Report(text, ctx);
  }

  protected binaryPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const ref = binConfigStr(config, "binaryArtifactReference") ?? binConfigStr(config, "binaryArtifactId");
    if (!ref) throw new AdapterConfigurationError("radare2 plan requires a registered binary artifact reference (worker-derived, §6)");
    const profileName = binConfigStr(config, "binaryAnalysisProfile") ?? "STANDARD";
    const profile = RADARE2_PROFILES[profileName];
    let operations: Radare2Operation[];
    const requested = config.binaryOperations;
    if (Array.isArray(requested) && requested.length > 0) {
      for (const op of requested) {
        if (typeof op !== "string" || !(RADARE2_OPERATIONS as readonly string[]).includes(op)) {
          throw new AdapterConfigurationError(`radare2 operation "${String(op)}" is not an approved typed operation (§34) — unrestricted r2 commands are rejected`);
        }
      }
      operations = requested as Radare2Operation[];
    } else if (profile) {
      operations = profile.operations;
    } else {
      throw new AdapterConfigurationError(`radare2 analysis profile "${profileName}" is not an approved profile (§33)`);
    }
    const batch = Radare2Adapter.composeCommand(operations);
    return { args: ["-2", "-q", "-c", batch, "--", ref] };
  }
}
