/**
 * Prompt 18 — reverse engineering & binary security analysis types
 * (§1–§95).
 *
 * The disciplines this module encodes end to end:
 *  - STATIC analysis is the DEFAULT and the norm: uploaded binaries
 *    are UNTRUSTED — hashed, identified by content (never extension),
 *    parsed — and NEVER executed during ingestion or static analysis
 *    (§8). No code path in this module launches a binary, loads it as
 *    code, runs an installer or invokes an entry point.
 *  - Runtime debugging exists ONLY as a governed policy + session
 *    architecture (§64–§74): LAB environment, explicit approval,
 *    isolated BINARY_DYNAMIC_LAB workers, typed operations only,
 *    kill switch, hard timeout, NO NETWORK by default. GDB is
 *    DISABLED outside the lab; pwndbg is APPROVAL_REQUIRED. Neither
 *    has an executing adapter in this build.
 *  - Commercial tools (IDA, Binary Ninja) are OPTIONAL connectors
 *    (§36–§39): license state is represented honestly
 *    (NOT_INSTALLED / INSTALLED / LICENSE_UNAVAILABLE / READY) and
 *    baseline analysis never depends on them (§96). Cutter is an
 *    ANALYST_TOOL (§35) — no invented headless capability.
 *  - Secrets found inside binaries persist as METADATA ONLY (§30):
 *    type, location, one-way fingerprint, redacted preview — reusing
 *    the P12 secret discipline. Private-key material never persists.
 *  - Extracted URLs/domains are DISCOVERED_REFERENCEs (§31/§32):
 *    they may LINK to already-authorized assets; they never
 *    authorize scanning and never expand scope.
 *  - Weaponization is out of scope BY CONSTRUCTION (§78/§123): no
 *    exploit generation, shellcode, ROP chains, payload injection,
 *    credential dumping, process injection, persistence, privilege
 *    escalation, sandbox escape or AV/EDR evasion exists anywhere.
 */
import type { NormalizedBinaryData } from "../findings/finding.types";

export type { BinaryFormatName, BinaryHardeningStatus, BinaryStringCategory, BinaryFindingType } from "../findings/finding.types";
export type { NormalizedBinaryData };

/** §9/§10: the two binary worker capabilities stay SEPARATE — static
 *  workers never debug and dynamic-lab workers are disposable,
 *  strongly isolated and never the general API/web workers. */
export const BINARY_WORKER_CAPABILITIES = {
  STATIC: "BINARY_STATIC_ANALYSIS",
  DYNAMIC_LAB: "BINARY_DYNAMIC_LAB",
} as const;

/** §3: where a binary artifact came from. Relationships preserve
 *  provenance without duplicating physical artifacts (§4). */
export type BinaryArtifactSource = "UPLOAD" | "MOBILE_BUILD" | "CONTAINER_IMAGE" | "SOURCE_BUILD" | "CONTROLLED_LAB";

/** §82: ScanBudget extensions for binary work. */
export interface BinaryScanBudget {
  maxBinarySizeMb: number;
  maxFunctions: number;
  maxStrings: number;
  maxSymbols: number;
  maxAnalysisSeconds: number;
  maxDecompileSeconds: number;
  maxProjectSizeMb: number;
  maxDebugDurationSeconds: number;
  maxCrashArtifacts: number;
  maxMemoryCaptureBytes: number;
}

export const DEFAULT_BINARY_BUDGET: BinaryScanBudget = {
  maxBinarySizeMb: 2048,
  maxFunctions: 200000,
  maxStrings: 50000,
  maxSymbols: 200000,
  maxAnalysisSeconds: 1800,
  maxDecompileSeconds: 1800,
  maxProjectSizeMb: 4096,
  maxDebugDurationSeconds: 1800,
  maxCrashArtifacts: 64,
  maxMemoryCaptureBytes: 16 * 1024 * 1024,
};

/** §78/§123: PROHIBITED AUTOMATION. These are never implemented,
 *  never plannable and never executable — the names exist so the
 *  policy can refuse them explicitly and auditably. */
export const PROHIBITED_BINARY_AUTOMATION = [
  "EXPLOIT_GENERATION",
  "WEAPONIZED_POC_GENERATION",
  "SHELLCODE_GENERATION",
  "ROP_CHAIN_GENERATION",
  "MALWARE_CREATION",
  "PAYLOAD_INJECTION",
  "CREDENTIAL_DUMPING",
  "PROCESS_INJECTION",
  "PERSISTENCE",
  "PRIVILEGE_ESCALATION",
  "SANDBOX_ESCAPE",
  "AV_EDR_EVASION",
  "DESTRUCTIVE_BINARY_EXECUTION",
  "ARBITRARY_GDB_COMMAND",
  "ARBITRARY_DEBUGGER_PYTHON",
  "ARBITRARY_GHIDRA_SCRIPT",
  "ARBITRARY_IDAPYTHON",
  "ARBITRARY_RADARE2_COMMAND",
  "UNRESTRICTED_DEBUGGER_SHELL",
] as const;
export type ProhibitedBinaryAction = (typeof PROHIBITED_BINARY_AUTOMATION)[number];

export function isProhibitedBinaryAction(value: string): boolean {
  return (PROHIBITED_BINARY_AUTOMATION as readonly string[]).includes(value.toUpperCase());
}

/** §64–§66: debugger registrations that NEVER execute outside the
 *  governed lab policy. Neither has an executing adapter — a debug
 *  session is a policy-governed record whose production transport is
 *  deliberately unwired in this build (sessions report
 *  NOT_PROVISIONED rather than fabricating a debugger). */
export interface BinaryDisabledRegistration {
  slug: string;
  name: string;
  capabilities: string[];
  executionState: "DISABLED" | "APPROVAL_REQUIRED" | "ANALYST_TOOL";
  reason: string;
}

export const BINARY_DISABLED_REGISTRATIONS: BinaryDisabledRegistration[] = [
  {
    slug: "gdb",
    name: "GDB (controlled debugging)",
    capabilities: ["DYNAMIC_DEBUGGING"],
    executionState: "DISABLED",
    reason: "Prompt 18 §65: GDB is DYNAMIC_DEBUGGING and DISABLED outside the LAB. It may run only inside a disposable BINARY_DYNAMIC_LAB worker for an authorized artifact under an approved BinaryDebugSession with typed operations (§67–§69). No executing adapter exists in this build.",
  },
  {
    slug: "pwndbg",
    name: "pwndbg (controlled debugging)",
    capabilities: ["DYNAMIC_DEBUGGING"],
    executionState: "APPROVAL_REQUIRED",
    reason: "Prompt 18 §66: pwndbg depends on GDB and is APPROVAL_REQUIRED — same lab + approval + typed-operation policy as GDB (§67). No executing adapter exists in this build.",
  },
  {
    slug: "cutter",
    name: "Cutter (analyst GUI)",
    capabilities: ["STATIC_BINARY_ANALYSIS", "DISASSEMBLY"],
    executionState: "ANALYST_TOOL",
    reason: "Prompt 18 §35: Cutter is registered as an ANALYST_TOOL — analysts use its GUI and may import exported artifacts/projects. DSRclone does not claim or invent unsupported headless Cutter automation.",
  },
];

/** §37: commercial connector license states — represented honestly,
 *  never bundled, never bypassed. */
export type CommercialLicenseState = "NOT_INSTALLED" | "INSTALLED" | "LICENSE_UNAVAILABLE" | "READY";

/** §95: the binary tool-health surface — every tool the spec names,
 *  with its worker type, risk, approval requirement and license. */
export interface BinaryToolDescriptor {
  slug: string;
  name: string;
  workerType: "BINARY_STATIC_ANALYSIS" | "BINARY_DYNAMIC_LAB" | "CONNECTOR" | "ANALYST_TOOL";
  risk: string;
  approvalRequirement: string;
  capabilities: string[];
  license: "OPEN_SOURCE" | "COMMERCIAL" | "ANALYST_PROVIDED";
}

export const BINARY_TOOL_DESCRIPTORS: BinaryToolDescriptor[] = [
  { slug: "ghidra", name: "Ghidra", workerType: "BINARY_STATIC_ANALYSIS", risk: "REVIEW_REQUIRED", approvalRequirement: "Administrator-approved scripts only (§20)", capabilities: ["BINARY_STATIC_ANALYSIS", "DISASSEMBLY", "DECOMPILATION", "FUNCTION_ANALYSIS", "IMPORT_EXPORT_ANALYSIS", "STRING_REFERENCE_ANALYSIS"], license: "OPEN_SOURCE" },
  { slug: "checksec", name: "checksec", workerType: "BINARY_STATIC_ANALYSIS", risk: "LOW", approvalRequirement: "None (static, sandboxed)", capabilities: ["BINARY_HARDENING_ANALYSIS"], license: "OPEN_SOURCE" },
  { slug: "radare2", name: "radare2", workerType: "BINARY_STATIC_ANALYSIS", risk: "REVIEW_REQUIRED", approvalRequirement: "Typed analysis profiles only (§34)", capabilities: ["STATIC_BINARY_ANALYSIS", "DISASSEMBLY", "FUNCTION_INVENTORY", "IMPORT_EXPORT_ANALYSIS", "STRING_ANALYSIS"], license: "OPEN_SOURCE" },
  { slug: "cutter", name: "Cutter", workerType: "ANALYST_TOOL", risk: "LOW", approvalRequirement: "Analyst workstation tool (§35)", capabilities: ["STATIC_BINARY_ANALYSIS", "DISASSEMBLY"], license: "OPEN_SOURCE" },
  { slug: "ida", name: "IDA", workerType: "CONNECTOR", risk: "REVIEW_REQUIRED", approvalRequirement: "Licensed installation + approved scripts only (§36–§38)", capabilities: ["STATIC_BINARY_ANALYSIS", "DISASSEMBLY", "DECOMPILATION"], license: "COMMERCIAL" },
  { slug: "binary-ninja", name: "Binary Ninja", workerType: "CONNECTOR", risk: "REVIEW_REQUIRED", approvalRequirement: "Licensed installation + API availability (§39)", capabilities: ["STATIC_BINARY_ANALYSIS", "DISASSEMBLY", "DECOMPILATION"], license: "COMMERCIAL" },
  { slug: "gdb", name: "GDB", workerType: "BINARY_DYNAMIC_LAB", risk: "HIGH", approvalRequirement: "LAB + approved debug session (§65/§67)", capabilities: ["DYNAMIC_DEBUGGING"], license: "OPEN_SOURCE" },
  { slug: "pwndbg", name: "pwndbg", workerType: "BINARY_DYNAMIC_LAB", risk: "HIGH", approvalRequirement: "LAB + approval (§66/§67)", capabilities: ["DYNAMIC_DEBUGGING"], license: "OPEN_SOURCE" },
];

/** A registered binary artifact as the worker/store resolve it (§3):
 *  identity (SHA-256) + bounded recorded analysis payload. The raw
 *  bytes never travel in this record — object-storage reference only. */
export interface BinaryArtifactRecord {
  id: string;
  workspaceId: string;
  name: string;
  source: BinaryArtifactSource;
  artifactReference?: string;
  sha256: string;
  sha1?: string;
  sizeBytes: number;
  format: string; // ELF | PE | MACH_O | UNKNOWN
  /** Bounded recorded analysis payload registered with the artifact
   *  (parsed header report, tool-output records, string inventory) —
   *  the static pipeline's input. Sanitized at intake. */
  analysisArtifacts?: Record<string, unknown>;
  status: string;
}

/** Connector dependencies for the commercial connectors (§36/§39).
 *  Transports are wired ONLY inside a worker against a licensed,
 *  administrator-provisioned installation — production deps leave
 *  them empty so connectors honestly report NOT_INSTALLED /
 *  NOT_CONFIGURED (§37/§96). */
export interface BinaryConnectorDeps {
  artifacts: {
    getArtifact(artifactId: string): Promise<BinaryArtifactRecord | undefined>;
    getArtifactByHash(workspaceId: string, sha256: string): Promise<BinaryArtifactRecord | undefined>;
  };
  transports: {
    ida?: { licenseState(): Promise<CommercialLicenseState>; fetchReport(artifactHash: string): Promise<string | undefined> };
    binaryNinja?: { licenseState(): Promise<CommercialLicenseState>; fetchReport(artifactHash: string): Promise<string | undefined> };
  };
}

/** INERT deps for plan-time registration: no registry, no transports —
 *  connectors report their honest unconfigured states, never data. */
export const INERT_BINARY_DEPS: BinaryConnectorDeps = {
  artifacts: {
    async getArtifact() { return undefined; },
    async getArtifactByHash() { return undefined; },
  },
  transports: {},
};

/** The parsed payload every Prompt 18 adapter produces: findings plus
 *  the normalized binary payload and dependency components. */
export interface ParsedBinary {
  findings: import("../findings/finding.types").NormalizedFinding[];
  binary?: NormalizedBinaryData;
  components?: import("../findings/finding.types").NormalizedSoftwareComponent[];
  metrics: Record<string, number>;
}

export function emptyParsedBinary(metrics: Record<string, number> = {}): ParsedBinary {
  return { findings: [], metrics };
}
