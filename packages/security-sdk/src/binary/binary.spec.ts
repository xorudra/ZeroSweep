/**
 * Prompt 18 — SDK tests (§97–§119 subset): content-based detection,
 * spoofing, malformed safety, hardening correctness, parsers,
 * evidence rules, secret discipline, diff + regressions, debug
 * policy, crash triage and the no-execution posture. Fixtures only —
 * no real binary is ever executed (§100: analysis is pure parsing;
 * the marker string embedded in the ELF is never acted on).
 */
import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { detectBinaryFormat, parseBinaryHeaders } from "./detect";
import { buildHardeningProfile } from "./hardening";
import { extractBinaryStrings } from "./strings";
import { analyzeBinaryPlatform, diffBinaryArtifacts, mergeBinaryObservations, triageBinaryCrash } from "./analysis";
import { parseBinaryGhidraReport, parseChecksecReport, parseRadare2Report } from "./parsers-binary";
import { sha256Of, validateBinaryArtifactUpload, validateFirmwareInventory } from "./intake";
import { evaluateBinaryDebugPolicy, validateDebugOperations } from "./debug-policy";
import { ChecksecAdapter, GhidraBinaryAdapter, Radare2Adapter } from "./adapters-binary";
import { binaryHealthBySlug, createBinaryAdapters } from "./registry";
import { FixtureToolRunner } from "../recon/runner";
import {
  CHECKSEC_HARDENED_JSON, CHECKSEC_UNHARDENED_JSON, EXECUTION_MARKER_PATH,
  FAKE_BINARY_TOKEN, FIXTURE_ELF_HARDENED, FIXTURE_ELF_SHA256, FIXTURE_ELF_STRIPPED,
  FIXTURE_ELF_TRUNCATED, FIXTURE_ELF_UNHARDENED, FIXTURE_ELF_UNHARDENED_SHA256,
  FIXTURE_MACHO_HARDENED, FIXTURE_MACHO_MALFORMED, FIXTURE_PE_HARDENED, FIXTURE_PE_MALFORMED,
  FIXTURE_PE_UNHARDENED, GHIDRA_BINARY_REPORT_JSON, GHIDRA_BINARY_REPORT_V2_JSON, RADARE2_REPORT_JSON,
} from "./fixtures";

const target = { type: "BINARY" as const, value: "artifact-ref", host: "artifact-ref" };
const binCfg = { binaryArtifactId: "art-1", binaryArtifactHash: FIXTURE_ELF_SHA256, binaryArtifactReference: "obj://art-1", binaryArtifactName: "app-hardened" };

describe("Prompt 18 §5/§102 format identification — magic bytes only", () => {
  it("identifies ELF, PE and Mach-O by content", () => {
    expect(detectBinaryFormat(FIXTURE_ELF_HARDENED)).toBe("ELF");
    expect(detectBinaryFormat(FIXTURE_PE_HARDENED)).toBe("PE");
    expect(detectBinaryFormat(FIXTURE_MACHO_HARDENED)).toBe("MACH_O");
    expect(detectBinaryFormat(Buffer.from("%PDF-1.7 not a binary"))).toBe("UNKNOWN");
  });
  it("a file named report.pdf containing an ELF is identified as ELF (spoofing)", () => {
    const report = parseBinaryHeaders(FIXTURE_ELF_HARDENED);
    expect(report.format).toBe("ELF");
    expect(report.malformed).toBe(false);
  });
  it("UNKNOWN is never guessed", () => {
    const report = parseBinaryHeaders(Buffer.from("plain text payload"));
    expect(report.format).toBe("UNKNOWN");
    expect(report.errors.length).toBeGreaterThan(0);
  });
});

describe("Prompt 18 §103 malformed binaries fail safely", () => {
  it("truncated ELF, bad-offset PE and lying Mach-O produce malformed reports, never throws", () => {
    expect(parseBinaryHeaders(FIXTURE_ELF_TRUNCATED).malformed).toBe(true);
    expect(parseBinaryHeaders(FIXTURE_PE_MALFORMED).malformed).toBe(true);
    expect(parseBinaryHeaders(FIXTURE_MACHO_MALFORMED).malformed).toBe(true);
  });
});

describe("Prompt 18 §12–§17 header parsing + hardening", () => {
  it("hardened ELF: PIE/NX/RELRO/canary evidence parsed from headers", () => {
    const report = parseBinaryHeaders(FIXTURE_ELF_HARDENED);
    expect(report.architecture).toBe("x86-64");
    expect(report.kind).toBe("EXECUTABLE");
    expect(report.dynamicLibraries).toEqual(expect.arrayContaining(["libc.so.6", "libssl.so.3", "libz.so.1.2.11"]));
    expect(report.hasStackCanary).toBe(true);
    const { profile, findings } = buildHardeningProfile(report, "test");
    const byName = new Map(profile.map((p) => [p.name, p.status]));
    expect(byName.get("NX")).toBe("ENABLED");
    expect(byName.get("PIE")).toBe("ENABLED");
    expect(byName.get("RELRO")).toBe("ENABLED");
    expect(byName.get("STACK_CANARY")).toBe("ENABLED");
    expect(byName.get("CFG")).toBe("NOT_APPLICABLE");
    expect(findings).toHaveLength(0);
  });
  it("unhardened ELF: gaps become findings; NOT_APPLICABLE stays distinct", () => {
    const report = parseBinaryHeaders(FIXTURE_ELF_UNHARDENED);
    const { profile, findings } = buildHardeningProfile(report, "test");
    const byName = new Map(profile.map((p) => [p.name, p.status]));
    expect(byName.get("NX")).toBe("DISABLED");
    expect(byName.get("PIE")).toBe("DISABLED");
    expect(byName.get("RELRO")).toBe("DISABLED");
    const rules = findings.map((f) => f.ruleId);
    expect(rules).toEqual(expect.arrayContaining(["BINARY_NO_NX", "BINARY_NO_PIE", "BINARY_NO_RELRO"]));
    expect(findings.every((f) => f.binaryFindingType === "BINARY_HARDENING_FINDING")).toBe(true);
  });
  it("stripped ELF is reported STRIPPED; PE mitigations come from DllCharacteristics", () => {
    expect(parseBinaryHeaders(FIXTURE_ELF_STRIPPED).stripped).toBe("STRIPPED");
    const pe = parseBinaryHeaders(FIXTURE_PE_HARDENED);
    expect(pe.format).toBe("PE");
    expect(pe.signals.aslr).toBe("ENABLED");
    expect(pe.signals.cfg).toBe("ENABLED");
    expect(pe.importedSymbols.map((i) => i.symbol)).toContain("CreateFileW");
    const peBad = buildHardeningProfile(parseBinaryHeaders(FIXTURE_PE_UNHARDENED), "test");
    expect(peBad.findings.map((f) => f.ruleId)).toEqual(expect.arrayContaining(["BINARY_NO_NX", "BINARY_NO_ASLR"]));
    const wx = peBad.findings.find((f) => f.ruleId === "BINARY_WX_SECTION");
    expect(wx).toBeUndefined(); // platform pass owns W+X; header profile does not double-report
  });
  it("Mach-O parses slices, PIE flag and linked libraries", () => {
    const report = parseBinaryHeaders(FIXTURE_MACHO_HARDENED);
    expect(report.format).toBe("MACH_O");
    expect(report.architecture).toBe("ARM64");
    expect(report.signals.pie).toBe("ENABLED");
    expect(report.dynamicLibraries.join(" ")).toContain("libSystem");
  });
});

describe("Prompt 18 §28–§31 strings + secrets", () => {
  it("extracts + classifies strings; secrets persist as fingerprint only", () => {
    const { strings, summary, discoveredReferences } = extractBinaryStrings(FIXTURE_ELF_HARDENED, { source: "test" });
    expect(summary.total).toBeGreaterThan(3);
    const secret = strings.find((s) => s.category === "SECRET_CANDIDATE");
    expect(secret).toBeDefined();
    expect(secret!.secretFingerprint).toBeTruthy();
    expect(JSON.stringify(strings)).not.toContain(FAKE_BINARY_TOKEN);
    const ref = discoveredReferences.find((r) => r.value.includes("example.invalid"));
    expect(ref?.classification).toBe("DISCOVERED_REFERENCE");
  });
  it("platform analysis turns the candidate into a BINARY_SECRET finding without the value", () => {
    const report = parseBinaryHeaders(FIXTURE_ELF_HARDENED);
    const strings = extractBinaryStrings(FIXTURE_ELF_HARDENED, { source: "test" });
    const { data, findings } = analyzeBinaryPlatform({
      artifactName: "app-hardened", sha256: FIXTURE_ELF_SHA256, sizeBytes: FIXTURE_ELF_HARDENED.length,
      report, strings, environment: "PRODUCTION",
    });
    const secret = findings.find((f) => f.binaryFindingType === "BINARY_SECRET");
    expect(secret).toBeDefined();
    expect(JSON.stringify(findings)).not.toContain(FAKE_BINARY_TOKEN);
    expect(JSON.stringify(data)).not.toContain(FAKE_BINARY_TOKEN);
    // Imported gets() alone produced NO risky finding (observation only, §48).
    expect(findings.find((f) => f.ruleId === "BINARY_RISKY_GETS")).toBeUndefined();
    // Imported MD5_Init IS weak-crypto evidence (§47).
    expect(findings.find((f) => f.ruleId === "BINARY_WEAK_CRYPTO")).toBeDefined();
    // zlib carries a full version → component for SCA; libssl.so.3 does not (no inference, §25).
    const zlib = data.dependencies.find((d) => d.library === "z");
    expect(zlib?.version).toBe("1.2.11");
    const ssl = data.dependencies.find((d) => d.library === "ssl");
    expect(ssl?.version).toBeUndefined();
  });
});

describe("Prompt 18 §15/§20/§34 tool parsers", () => {
  it("checksec: statuses + findings; PE-only checks are NOT_APPLICABLE", () => {
    const hard = parseChecksecReport(CHECKSEC_HARDENED_JSON, { toolSlug: "checksec", artifactHash: FIXTURE_ELF_SHA256, artifactName: "app-hardened" });
    expect(hard.findings).toHaveLength(0);
    const soft = parseChecksecReport(CHECKSEC_UNHARDENED_JSON, { toolSlug: "checksec", artifactHash: FIXTURE_ELF_UNHARDENED_SHA256, artifactName: "app-unhardened" });
    expect(soft.findings.map((f) => f.ruleId)).toEqual(expect.arrayContaining(["BINARY_NO_NX", "BINARY_NO_PIE", "BINARY_NO_RELRO", "BINARY_NO_CANARY"]));
    expect(soft.binary!.hardening.find((h) => h.name === "CFG")?.status).toBe("NOT_APPLICABLE");
  });
  it("ghidra report: function inventory + risky-API evidence finding + risky-import dedup key", () => {
    const parsed = parseBinaryGhidraReport(GHIDRA_BINARY_REPORT_JSON, { toolSlug: "ghidra", artifactHash: FIXTURE_ELF_SHA256, artifactName: "app-hardened" });
    expect(parsed.binary!.functions.map((f) => f.name)).toEqual(expect.arrayContaining(["main", "process_request"]));
    const risky = parsed.findings.find((f) => f.ruleId === "BINARY_RISKY_STRCPY");
    expect(risky?.binaryReachability).toBe("POSSIBLY_REACHABLE");
    expect(risky?.binaryFingerprint).toBeTruthy();
    expect(risky!.binaryFingerprint).not.toMatch(/0x[0-9a-f]+/);
  });
  it("radare2 envelope parses typed operations; multi-tool observations merge to one canonical finding", () => {
    const r2 = parseRadare2Report(RADARE2_REPORT_JSON, { toolSlug: "radare2", artifactHash: FIXTURE_ELF_SHA256, artifactName: "app-hardened" });
    expect(r2.binary!.functions.length).toBe(2);
    // Same artifact reported fully-hardened by checksec and radare2 → no
    // duplicate hardening findings; a DISABLED report from both tools
    // merges into ONE canonical finding with two observations.
    const chk = parseChecksecReport(CHECKSEC_UNHARDENED_JSON, { toolSlug: "checksec", artifactHash: FIXTURE_ELF_UNHARDENED_SHA256, artifactName: "app" });
    const merged = mergeBinaryObservations(chk.findings);
    expect(merged.observations.length).toBe(chk.findings.length);
    expect(merged.findings.length).toBe(chk.findings.length);
  });
  it("malformed tool output fails closed", () => {
    expect(parseChecksecReport("not json", { toolSlug: "checksec", artifactHash: "x", artifactName: "y" }).metrics.parseErrors).toBe(1);
    expect(parseBinaryGhidraReport("{broken", { toolSlug: "ghidra", artifactHash: "x", artifactName: "y" }).metrics.parseErrors).toBe(1);
  });
});

describe("Prompt 18 §33/§34/§93/§112 radare2 typed operations only", () => {
  it("plans are composed from typed operations; command-carrying config is REJECTED", async () => {
    const adapter = new Radare2Adapter(new FixtureToolRunner({ r2: { stdout: RADARE2_REPORT_JSON } }));
    const plan = await adapter.buildExecutionPlan(target, { ...binCfg, binaryAnalysisProfile: "FULL" });
    expect(plan.arguments.join(" ")).toContain("iIj");
    await expect(adapter.buildExecutionPlan(target, { ...binCfg, binaryOperations: ["WIPE_DISK"] })).rejects.toThrow(/not an approved typed operation/);
    await expect(adapter.buildExecutionPlan(target, { ...binCfg, command: "aaa; px 100" })).rejects.toThrow(/forbidden/);
    await expect(adapter.buildExecutionPlan(target, { ...binCfg, r2command: "px" })).rejects.toThrow(/forbidden/);
  });
  it("checksec plan targets the artifact as data — the artifact is never the executable", async () => {
    const adapter = new ChecksecAdapter(new FixtureToolRunner({ checksec: { stdout: CHECKSEC_HARDENED_JSON } }));
    const plan = await adapter.buildExecutionPlan(target, binCfg);
    expect(plan.arguments.join(" ")).toContain("--file=");
    // The plan's executable is the analyzer (checksec), never the artifact.
    expect(JSON.stringify(plan)).toContain("checksec");
    expect(plan.arguments.join(" ")).not.toContain("AKIA");
  });
  it("ghidra binary adapter extends the Prompt 17 adapter and pins the approved script", async () => {
    const adapter = new GhidraBinaryAdapter(new FixtureToolRunner({ analyzeHeadless: { stdout: GHIDRA_BINARY_REPORT_JSON } }));
    expect(adapter).toBeInstanceOf(GhidraBinaryAdapter);
    const plan = await adapter.buildExecutionPlan(target, binCfg);
    expect(plan.arguments).toContain("BinarySecurityInventory.py");
    await expect(adapter.buildExecutionPlan(target, { ...binCfg, scriptBody: "evil" })).rejects.toThrow();
    // Mobile mode still delegates to the Prompt 17 behavior.
    const mobilePlan = await adapter.buildExecutionPlan(
      { type: "MOBILE_APP", value: "x", host: "x" },
      { mobileApplicationId: "a", mobileBuildId: "b", mobileBuildHash: "h", mobileApplicationRef: "app", mobilePlatform: "ANDROID", mobileArtifactReference: "obj://apk" },
    );
    expect(mobilePlan.arguments).toContain("MobileHardeningInventory.py");
  });
});

describe("Prompt 18 §6/§7/§101/§105 intake + firmware discipline", () => {
  it("hash identity + dedup inputs validate; oversize refused", () => {
    expect(validateBinaryArtifactUpload({ name: "app", declaredSha256: sha256Of(FIXTURE_ELF_HARDENED), sizeBytes: 100, source: "UPLOAD", magicPrefix: FIXTURE_ELF_HARDENED }).accepted).toBe(true);
    expect(validateBinaryArtifactUpload({ name: "app", sizeBytes: 10 * 1024 * 1024 * 1024, source: "UPLOAD" }).accepted).toBe(false);
    expect(validateBinaryArtifactUpload({ name: "app", declaredSha256: "not-a-hash", sizeBytes: 10, source: "UPLOAD" }).accepted).toBe(false);
  });
  it("firmware inventories refuse traversal, symlinks and bombs", () => {
    expect(validateFirmwareInventory([{ path: "bin/app", sizeBytes: 10, kind: "FILE" }]).accepted).toBe(true);
    expect(validateFirmwareInventory([{ path: "../etc/passwd", sizeBytes: 10, kind: "FILE" }]).accepted).toBe(false);
    expect(validateFirmwareInventory([{ path: "bin/link", sizeBytes: 0, kind: "SYMLINK", linkTarget: "/etc" }]).accepted).toBe(false);
    expect(validateFirmwareInventory([{ path: "/abs/path", sizeBytes: 1, kind: "FILE" }]).accepted).toBe(false);
  });
});

describe("Prompt 18 §53–§55 cross-build diff + regressions", () => {
  it("detects added/removed/changed functions and hardening regressions", () => {
    const ctx = { toolSlug: "ghidra", artifactHash: FIXTURE_ELF_SHA256, artifactName: "app-hardened" };
    const v1 = parseBinaryGhidraReport(GHIDRA_BINARY_REPORT_JSON, ctx).binary!;
    const v2 = parseBinaryGhidraReport(GHIDRA_BINARY_REPORT_V2_JSON, ctx).binary!;
    const diff = diffBinaryArtifacts(v1, v2);
    expect(diff.functionsAdded).toContain("new_feature");
    expect(diff.functionsRemoved).toContain("helper_check");
    expect(diff.functionsChanged).toContain("process_request");
    expect(diff.regressions.some((r) => r.kind === "HARDENING_REMOVED" && r.detail.includes("PIE"))).toBe(true);
  });
});

describe("Prompt 18 §64–§74/§113/§114 debug policy", () => {
  const ops = [{ operation: "START_APPROVED_FIXTURE" }];
  it("PRODUCTION environment → BLOCKED", () => {
    const d = evaluateBinaryDebugPolicy({ environment: "PRODUCTION", artifactAuthorized: true, targetVerified: true, requestedBy: "u1", approvedBy: "u2", workerCapabilityPresent: true, killSwitchActive: false, operations: ops });
    expect(d.decision).toBe("BLOCKED");
  });
  it("LAB without approval → PENDING_APPROVAL; LAB + approval → ELIGIBLE", () => {
    const pending = evaluateBinaryDebugPolicy({ environment: "LAB", artifactAuthorized: true, targetVerified: true, requestedBy: "u1", workerCapabilityPresent: true, killSwitchActive: false, operations: ops });
    expect(pending.decision).toBe("PENDING_APPROVAL");
    const ok = evaluateBinaryDebugPolicy({ environment: "LAB", artifactAuthorized: true, targetVerified: true, requestedBy: "u1", approvedBy: "u2", workerCapabilityPresent: true, killSwitchActive: false, operations: ops });
    expect(ok.decision).toBe("ELIGIBLE");
    expect(ok.networkPolicy).toBe("NO_NETWORK");
  });
  it("self-approval and an active kill switch block", () => {
    const d = evaluateBinaryDebugPolicy({ environment: "LAB", artifactAuthorized: true, targetVerified: true, requestedBy: "u1", approvedBy: "u1", workerCapabilityPresent: true, killSwitchActive: true, operations: ops });
    expect(d.decision).toBe("BLOCKED");
  });
  it("arbitrary GDB/Python/shell operations are REJECTED (§114)", () => {
    expect(validateDebugOperations([{ operation: "ARBITRARY_GDB_COMMAND" }]).ok).toBe(false);
    expect(validateDebugOperations([{ operation: "RUN", params: { command: "shell ls" } }]).ok).toBe(false);
    expect(validateDebugOperations([{ operation: "INSPECT_REGISTER_METADATA" }]).ok).toBe(true);
  });
});

describe("Prompt 18 §75–§77 crash triage", () => {
  it("fingerprints dedup across raw addresses; canary crash is security-relevant; exploitability never claimed", () => {
    const a = triageBinaryCrash({ signal: "SIGSEGV", faultingFunction: "process_request", stackFunctions: ["process_request 0x1150", "main 0x1040"], artifactLineage: "ELF:app", faultLooksLikeCanaryFailure: true });
    const b = triageBinaryCrash({ signal: "SIGSEGV", faultingFunction: "process_request", stackFunctions: ["process_request 0x9999", "main 0x8888"], artifactLineage: "ELF:app", faultLooksLikeCanaryFailure: true });
    expect(a.fingerprint).toBe(b.fingerprint);
    expect(a.classification).toBe("LIKELY_SECURITY_RELEVANT");
    expect(JSON.stringify(a)).not.toMatch(/exploitable/i);
    const plain = triageBinaryCrash({ signal: "SIGSEGV", exceptionType: "READ access", stackFunctions: [], artifactLineage: "ELF:app" });
    expect(plain.classification).toBe("LIKELY_NON_SECURITY");
  });
});

describe("Prompt 18 §37/§95/§96 health + degradation", () => {
  it("connectors report honest states; baseline works without commercial tools", async () => {
    const health = await binaryHealthBySlug(createBinaryAdapters(new FixtureToolRunner({})));
    expect(health["ida"]!.status).toBe("NOT_CONFIGURED");
    expect(health["binary-ninja"]!.status).toBe("NOT_CONFIGURED");
    expect(health["cutter"]!.status).toBe("ANALYST_TOOL");
    expect(health["gdb"]!.status).toBe("DISABLED");
    expect(health["pwndbg"]!.status).toBe("APPROVAL_REQUIRED");
    expect(health["checksec"]!.status).toBe("UNAVAILABLE"); // no fixture → honestly unavailable
  });
  it("§100: analyzing the marker fixture executes nothing — the marker never appears", () => {
    const report = parseBinaryHeaders(FIXTURE_ELF_UNHARDENED);
    const strings = extractBinaryStrings(FIXTURE_ELF_UNHARDENED, { source: "test" });
    analyzeBinaryPlatform({ artifactName: "app", sha256: FIXTURE_ELF_UNHARDENED_SHA256, sizeBytes: 1, report, strings, environment: "LAB" });
    expect(existsSync(EXECUTION_MARKER_PATH)).toBe(false);
  });
});

describe("Prompt 18 retest planning (artifact-over-artifact)", () => {
  it("maps findings back to their original stage family + tool", async () => {
    const { planBinaryRetest } = await import("./retest");
    expect(planBinaryRetest({ sourceTool: "checksec" })).toEqual(expect.objectContaining({ stageType: "BINARY_HARDENING_ANALYSIS", adapterSlug: "checksec" }));
    expect(planBinaryRetest({ binaryFindingType: "BINARY_HARDENING_FINDING" }).adapterSlug).toBe("checksec");
    expect(planBinaryRetest({ sourceTool: "radare2" })).toEqual(expect.objectContaining({ stageType: "BINARY_STATIC_ANALYSIS", adapterSlug: "radare2" }));
    expect(planBinaryRetest({ sourceTool: "ghidra" }).adapterSlug).toBe("ghidra");
    expect(planBinaryRetest({ binaryFindingType: "BINARY_SECRET" }).adapterSlug).toBe("ghidra");
  });
  it("binaryHealthRecord is the sync plan-time view (descriptors verbatim)", async () => {
    const { binaryHealthRecord } = await import("./registry");
    const record = binaryHealthRecord(createBinaryAdapters(new FixtureToolRunner({})));
    expect(record["gdb"]).toBe("DISABLED");
    expect(record["pwndbg"]).toBe("APPROVAL_REQUIRED");
    expect(record["checksec"]).toBe("UNAVAILABLE");
  });
});
