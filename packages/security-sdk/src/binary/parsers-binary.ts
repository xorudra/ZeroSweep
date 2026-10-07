/**
 * Prompt 18 — tool-output parsers (§15/§21/§34).
 *
 * checksec JSON, the Ghidra headless platform report and the radare2
 * typed-operation envelope are machine-generated, size-bounded and
 * FAIL CLOSED: malformed or hostile output (oversized payloads,
 * HTML/terminal-escape strings, invalid Unicode) is sanitized by the
 * shared bounded parsers — parsers never throw hostile shapes upward
 * and never persist raw secret-shaped strings.
 */
import { parseBoundedMobileJson, sanitizeMobileText } from "../mobile/sanitize";
import type {
  BinaryHardeningStatus, NormalizedBinaryData, NormalizedBinaryDependency,
  NormalizedFinding,
} from "../findings/finding.types";
import { binaryFindingFingerprint, dependencyFromLibraryName, riskyApiFindings } from "./analysis";
import { emptyParsedBinary, type ParsedBinary } from "./types";

export interface BinaryParserContext {
  toolSlug: string;
  artifactId?: string;
  artifactHash: string;
  artifactName: string;
}

type Rec = Record<string, unknown>;
const rec = (v: unknown): Rec => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? sanitizeMobileText(v, 1024) : undefined);
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

function baseData(ctx: BinaryParserContext, source: string): NormalizedBinaryData {
  return {
    artifactName: ctx.artifactName, sha256: ctx.artifactHash, format: "UNKNOWN",
    compilerHints: [], sections: [], hardening: [], functions: [], imports: [],
    exports: [], symbols: [], dependencies: [], strings: [],
    stringsSummary: { total: 0, byCategory: {} }, cryptoReferences: [],
    discoveredReferences: [], source,
  };
}

function hardeningGapFinding(ctx: BinaryParserContext, source: string, name: string, ruleId: string, status: BinaryHardeningStatus, lineage: string): NormalizedFinding {
  return {
    title: `Binary missing ${name} mitigation`,
    description: `${source} reports ${name} as ${status} for this artifact. Hardening reduces the impact of memory-safety defects; its absence is a configuration-class weakness, not proof a vulnerability exists (§17).`,
    severity: ruleId === "BINARY_NO_NX" || ruleId === "BINARY_NO_PIE" || ruleId === "BINARY_NO_ASLR" ? "MEDIUM" : "LOW",
    confidence: 0.9, cwe: "CWE-693", references: [], sourceTool: source,
    sourceFingerprint: `${source}:${ruleId}:${ctx.artifactHash.slice(0, 12)}`, ruleId,
    binaryFindingType: "BINARY_HARDENING_FINDING", binaryComponent: name,
    binaryReachability: "UNKNOWN", staticConfidence: "HIGH",
    binaryArtifactHash: ctx.artifactHash,
    binaryFingerprint: binaryFindingFingerprint({ lineage, component: name, ruleId, cwe: "CWE-693", findingClass: "BINARY_HARDENING_FINDING", location: name }),
  };
}

// ── checksec (§15) ──────────────────────────────────────────────────

const CHECKSEC_MAP: Record<string, { name: string; ruleId?: string; status: (v: string) => BinaryHardeningStatus }> = {
  nx: { name: "NX", ruleId: "BINARY_NO_NX", status: (v) => (/enabled/i.test(v) ? "ENABLED" : /disabled/i.test(v) ? "DISABLED" : "UNKNOWN") },
  pie: { name: "PIE", ruleId: "BINARY_NO_PIE", status: (v) => (/enabled/i.test(v) ? "ENABLED" : /no pie/i.test(v) ? "DISABLED" : /dso/i.test(v) ? "ENABLED" : "UNKNOWN") },
  relro: { name: "RELRO", ruleId: "BINARY_NO_RELRO", status: (v) => (/full/i.test(v) ? "ENABLED" : /partial/i.test(v) ? "PARTIAL" : /no relro/i.test(v) ? "DISABLED" : "UNKNOWN") },
  canary: { name: "STACK_CANARY", ruleId: "BINARY_NO_CANARY", status: (v) => (/no canary/i.test(v) ? "DISABLED" : /found/i.test(v) ? "ENABLED" : "UNKNOWN") },
  fortify_source: { name: "FORTIFY", status: (v) => (/enabled/i.test(v) ? "ENABLED" : /disabled/i.test(v) ? "DISABLED" : "UNKNOWN") },
};

export function parseChecksecReport(text: string, ctx: BinaryParserContext): ParsedBinary {
  const source = ctx.toolSlug;
  const root = rec(parseBoundedMobileJson(text, { what: "checksec report" }));
  const firstKey = Object.keys(root)[0];
  const entry = firstKey ? rec(root[firstKey]) : {};
  if (!firstKey || Object.keys(entry).length === 0) return emptyParsedBinary({ parseErrors: 1 });
  const data = baseData(ctx, source);
  const lineage = `artifact:${ctx.artifactHash}`;
  const findings: NormalizedFinding[] = [];
  for (const [key, spec] of Object.entries(CHECKSEC_MAP)) {
    const raw = entry[key];
    if (typeof raw !== "string") { data.hardening.push({ name: spec.name, status: "UNKNOWN", detail: "checksec did not report this mitigation", source }); continue; }
    const status = spec.status(raw);
    data.hardening.push({ name: spec.name, status, detail: sanitizeMobileText(raw, 120), source });
    if (spec.ruleId && (status === "DISABLED" || (spec.name === "RELRO" && status === "PARTIAL"))) {
      findings.push(hardeningGapFinding(ctx, source, spec.name, status === "PARTIAL" ? "BINARY_PARTIAL_RELRO" : spec.ruleId, status, lineage));
    }
  }
  // Properties that do not apply to this artifact stay NOT_APPLICABLE.
  for (const name of ["CFG", "SAFESH", "CODE_SIGNING"]) {
    data.hardening.push({ name, status: "NOT_APPLICABLE", detail: "PE mitigation — checksec assesses ELF artifacts", source });
  }
  if (typeof entry.symbols === "string") {
    data.stripped = /no symbols/i.test(entry.symbols) ? "STRIPPED" : "NOT_STRIPPED";
  }
  return { findings, binary: data, metrics: { hardeningChecked: data.hardening.length } };
}

// ── Ghidra headless platform report (§20/§21) ──────────────────────

export function parseBinaryGhidraReport(text: string, ctx: BinaryParserContext): ParsedBinary {
  const source = ctx.toolSlug;
  const root = rec(parseBoundedMobileJson(text, { what: "ghidra binary report" }));
  if (Object.keys(root).length === 0) return emptyParsedBinary({ parseErrors: 1 });
  const data = baseData(ctx, source);
  const program = rec(root.program);
  const fmt = str(program.format);
  data.format = fmt === "ELF" || fmt === "PE" || fmt === "MACH_O" ? fmt : "UNKNOWN";
  if (str(program.architecture)) data.architecture = str(program.architecture);
  if (str(program.name)) data.artifactName = str(program.name);
  if (str(program.entryPoint)) data.entryPoint = str(program.entryPoint);
  for (const s of arr(root.sections)) {
    const r = rec(s);
    data.sections.push({
      name: str(r.name) ?? "section", ...(str(r.type) ? { type: str(r.type) } : {}),
      ...(num(r.offset) !== undefined ? { offset: num(r.offset) } : {}),
      ...(num(r.size) !== undefined ? { size: num(r.size) } : {}),
      ...(str(r.virtualAddress) ? { virtualAddress: str(r.virtualAddress) } : {}),
      ...(str(r.permissions) ? { permissions: str(r.permissions) } : {}),
      ...(num(r.entropy) !== undefined ? { entropy: num(r.entropy) } : {}),
      source,
    });
  }
  for (const f of arr(root.functions)) {
    const r = rec(f);
    const name = str(r.name);
    if (!name) continue;
    data.functions.push({
      name, ...(str(r.address) ? { address: str(r.address) } : {}),
      ...(num(r.size) !== undefined ? { size: num(r.size) } : {}),
      ...(str(r.callingConvention) ? { callingConvention: str(r.callingConvention) } : {}),
      source, confidence: num(r.confidence) ?? 0.7,
      ...(str(r.fingerprint) ? { fingerprint: str(r.fingerprint) } : {}),
      ...(arr(r.referencesRiskyApi).length ? { referencesRiskyApi: arr(r.referencesRiskyApi).filter((x): x is string => typeof x === "string") } : {}),
    });
  }
  for (const i of arr(root.imports)) {
    const r = rec(i);
    if (str(r.symbol)) data.imports.push({ library: str(r.library) ?? "unknown", symbol: str(r.symbol)!, ...(str(r.address) ? { address: str(r.address) } : {}), source });
  }
  for (const e of arr(root.exports)) {
    const r = rec(e);
    if (str(r.symbol)) data.exports.push({ symbol: str(r.symbol)!, ...(str(r.address) ? { address: str(r.address) } : {}), ...(str(r.type) ? { type: str(r.type) } : {}), source });
  }
  for (const s of arr(root.symbols)) {
    const r = rec(s);
    if (str(r.name)) data.symbols.push({ name: str(r.name)!, ...(str(r.type) ? { type: str(r.type) } : {}), ...(str(r.binding) ? { binding: str(r.binding) } : {}), ...(str(r.address) ? { address: str(r.address) } : {}), source });
  }
  for (const l of arr(root.libraries)) {
    const r = rec(l);
    const name = str(r.name) ?? str(r.path);
    if (!name) continue;
    const dep: NormalizedBinaryDependency = str(r.version)
      ? { library: name, version: str(r.version), sourceKind: "DECLARED", confidence: 0.9, source, ...(str(r.version) ? { purl: `pkg:generic/${name}@${str(r.version)}` } : {}) }
      : dependencyFromLibraryName(name, source, "DETECTED_LINKED");
    data.dependencies.push(dep);
  }
  const hard = rec(root.hardening);
  for (const [name, rawStatus] of Object.entries(hard)) {
    const st = typeof rawStatus === "string" && ["ENABLED", "DISABLED", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN"].includes(rawStatus) ? (rawStatus as BinaryHardeningStatus) : "UNKNOWN";
    data.hardening.push({ name: name.toUpperCase(), status: st, source });
  }
  const findings = riskyApiFindings(data, source);
  return { findings, binary: data, metrics: { functions: data.functions.length, imports: data.imports.length, exports: data.exports.length } };
}

// ── radare2 typed operations (§34) ────────────────────────────────

export const RADARE2_OPERATIONS = ["METADATA", "SECTIONS", "IMPORTS", "EXPORTS", "FUNCTIONS", "STRINGS", "SYMBOLS"] as const;
export type Radare2Operation = (typeof RADARE2_OPERATIONS)[number];

/** Typed operation → the FIXED radare2 command fragment the ADAPTER
 *  composes. User input never becomes a command (§34/§112). */
export const RADARE2_OPERATION_COMMANDS: Record<Radare2Operation, string> = {
  METADATA: "iIj",
  SECTIONS: "iSj",
  IMPORTS: "iij",
  EXPORTS: "iEj",
  FUNCTIONS: "aflj",
  STRINGS: "izj",
  SYMBOLS: "isj",
};

export function parseRadare2Report(text: string, ctx: BinaryParserContext): ParsedBinary {
  const source = ctx.toolSlug;
  const root = parseBoundedMobileJson(text, { what: "radare2 report" });
  const ops = arr(root);
  if (ops.length === 0) return emptyParsedBinary({ parseErrors: 1 });
  const data = baseData(ctx, source);
  for (const opEntry of ops) {
    const envelope = rec(opEntry);
    const op = str(envelope.op);
    const payload = envelope.data;
    if (op === "METADATA") {
      const m = rec(payload);
      const fmt = str(m.format) ?? str(m.bintype);
      data.format = fmt === "ELF" || fmt === "PE" || fmt === "MACH_O" ? fmt : data.format;
      if (str(m.arch)) data.architecture = `${str(m.arch)}${num(m.bits) ? `-${num(m.bits)}` : ""}`;
      if (num(m.bits)) data.bitness = num(m.bits) === 64 ? 64 : 32;
      if (typeof m.stripped === "boolean") data.stripped = m.stripped ? "STRIPPED" : "NOT_STRIPPED";
      if (typeof m.canary === "boolean") data.hardening.push({ name: "STACK_CANARY", status: m.canary ? "ENABLED" : "DISABLED", source });
      if (typeof m.nx === "boolean") data.hardening.push({ name: "NX", status: m.nx ? "ENABLED" : "DISABLED", source });
      if (typeof m.pie === "boolean") data.hardening.push({ name: "PIE", status: m.pie ? "ENABLED" : "DISABLED", source });
      if (typeof m.relro === "string") data.hardening.push({ name: "RELRO", status: /full/i.test(m.relro as string) ? "ENABLED" : /partial/i.test(m.relro as string) ? "PARTIAL" : "DISABLED", source });
    } else if (op === "SECTIONS") {
      for (const s of arr(payload)) {
        const r = rec(s);
        data.sections.push({
          name: str(r.name) ?? "section", ...(num(r.p_offset) !== undefined ? { offset: num(r.p_offset) } : {}),
          ...(num(r.vsize) !== undefined ? { size: num(r.vsize) } : {}),
          ...(num(r.vaddr) !== undefined ? { virtualAddress: `0x${num(r.vaddr)!.toString(16)}` } : {}),
          ...(str(r.perm) ? { permissions: (str(r.perm) ?? "").toUpperCase() } : {}),
          source,
        });
      }
    } else if (op === "IMPORTS") {
      for (const i of arr(payload)) {
        const r = rec(i);
        if (str(r.name)) data.imports.push({ library: str(r.libname) ?? str(r.library) ?? "unknown", symbol: str(r.name)!, ...(num(r.plt) !== undefined ? { address: `0x${num(r.plt)!.toString(16)}` } : {}), source });
      }
    } else if (op === "EXPORTS") {
      for (const e of arr(payload)) {
        const r = rec(e);
        if (str(r.name)) data.exports.push({ symbol: str(r.name)!, ...(num(r.vaddr) !== undefined ? { address: `0x${num(r.vaddr)!.toString(16)}` } : {}), source });
      }
    } else if (op === "FUNCTIONS") {
      for (const f of arr(payload)) {
        const r = rec(f);
        if (!str(r.name)) continue;
        data.functions.push({
          name: str(r.name)!, ...(num(r.offset) !== undefined ? { address: `0x${num(r.offset)!.toString(16)}` } : {}),
          ...(num(r.size) !== undefined ? { size: num(r.size) } : {}),
          source, confidence: 0.7,
        });
      }
    } else if (op === "SYMBOLS") {
      for (const s of arr(payload)) {
        const r = rec(s);
        if (str(r.name)) data.symbols.push({ name: str(r.name)!, ...(str(r.type) ? { type: str(r.type) } : {}), ...(str(r.bind) ? { binding: str(r.bind) } : {}), source });
      }
    }
  }
  const findings: NormalizedFinding[] = [];
  const lineage = `artifact:${ctx.artifactHash}`;
  for (const h of data.hardening) {
    if (h.status === "DISABLED") {
      const ruleId = h.name === "NX" ? "BINARY_NO_NX" : h.name === "PIE" ? "BINARY_NO_PIE" : h.name === "STACK_CANARY" ? "BINARY_NO_CANARY" : h.name === "RELRO" ? "BINARY_NO_RELRO" : undefined;
      if (ruleId) findings.push(hardeningGapFinding(ctx, source, h.name, ruleId, h.status, lineage));
    }
  }
  return { findings, binary: data, metrics: { functions: data.functions.length, imports: data.imports.length, sections: data.sections.length } };
}
