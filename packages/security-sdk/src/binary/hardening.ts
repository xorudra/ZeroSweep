/**
 * Prompt 18 — binary hardening profile + findings (§16/§17).
 *
 * Mitigations are normalized to ENABLED / DISABLED / PARTIAL /
 * NOT_APPLICABLE / UNKNOWN from HEADER EVIDENCE ONLY — a tool's "N/A"
 * never becomes disabled, and absence of evidence stays UNKNOWN.
 * Missing mitigations are findings ONLY where relevant (a shared
 * library does not get a "missing PIE executable" finding), and the
 * risk text is contextual: hardening REDUCES impact; it is not proof
 * a vulnerability exists (§17).
 */
import type { BinaryHardeningStatus, NormalizedBinaryHardening, NormalizedFinding } from "../findings/finding.types";
import type { BinaryHeaderReport } from "./detect";

const S = (status: BinaryHardeningStatus) => status;

export interface HardeningProfileResult {
  profile: NormalizedBinaryHardening[];
  findings: NormalizedFinding[];
}

export function buildHardeningProfile(report: BinaryHeaderReport, source: string): HardeningProfileResult {
  const profile: NormalizedBinaryHardening[] = [];
  const add = (name: string, status: BinaryHardeningStatus, detail?: string) => {
    profile.push({ name, status, ...(detail ? { detail } : {}), source });
  };
  const sig = report.signals;

  if (report.format === "ELF") {
    add("NX", sig.gnuStack === "NON_EXECUTABLE" ? S("ENABLED") : sig.gnuStack === "EXECUTABLE" ? S("DISABLED") : S("UNKNOWN"),
      sig.gnuStack === "ABSENT" ? "No PT_GNU_STACK segment — stack executability not determinable from headers" : undefined);
    add("PIE", report.kind === "OBJECT" ? S("NOT_APPLICABLE") : sig.pieType === "DYN" ? S("ENABLED") : sig.pieType === "EXEC" ? S("DISABLED") : S("UNKNOWN"));
    add("RELRO", sig.gnuRelro === "PRESENT" ? (sig.bindNow === "PRESENT" ? S("ENABLED") : S("PARTIAL")) : S("DISABLED"),
      sig.gnuRelro === "PRESENT" && sig.bindNow !== "PRESENT" ? "GNU_RELRO present without BIND_NOW = partial RELRO" : undefined);
    add("STACK_CANARY", report.hasStackCanary ? S("ENABLED") : S("DISABLED"));
    add("FORTIFY", report.fortifySymbols ? S("PARTIAL") : S("UNKNOWN"), report.fortifySymbols ? "Some *_chk fortified functions observed; coverage ratio needs tool evidence" : "No fortified *_chk symbols observed — FORTIFY coverage is UNKNOWN, not disabled");
    add("ASLR", sig.pieType === "DYN" ? S("ENABLED") : sig.pieType === "EXEC" ? S("DISABLED") : S("UNKNOWN"), "Derived from PIE: a non-PIE executable loads at a fixed address");
    add("CFG", S("NOT_APPLICABLE"), "Control Flow Guard is a PE mitigation");
    add("SAFESH", S("NOT_APPLICABLE"), "SafeSEH is a 32-bit PE mitigation");
    add("CODE_SIGNING", S("UNKNOWN"), "ELF code-signing state is not determinable from headers");
  } else if (report.format === "PE") {
    add("NX", (sig.nx as BinaryHardeningStatus) ?? S("UNKNOWN"), "PE NX_COMPAT (DllCharacteristics)");
    add("ASLR", (sig.aslr as BinaryHardeningStatus) ?? S("UNKNOWN"), "PE DYNAMIC_BASE (DllCharacteristics)");
    add("CFG", (sig.cfg as BinaryHardeningStatus) ?? S("UNKNOWN"), "PE GUARD_CF (DllCharacteristics)");
    add("SAFESH", report.bitness === 64 ? S("NOT_APPLICABLE") : sig.safeSeh === "PRESENT_CHECK" ? S("UNKNOWN") : S("DISABLED"),
      report.bitness === 64 ? "SafeSEH does not apply to 64-bit PE" : "NO_SEH flag absent; SafeSEH table presence needs tool evidence");
    add("CODE_SIGNING", sig.codeSigning === "PRESENT" ? S("ENABLED") : S("DISABLED"), "Authenticode security directory");
    add("PIE", S("NOT_APPLICABLE"), "PIE is the ELF model; the PE equivalent is ASLR/DYNAMIC_BASE");
    add("RELRO", S("NOT_APPLICABLE"), "RELRO is an ELF mitigation");
    add("STACK_CANARY", S("UNKNOWN"), "PE /GS cookie presence needs tool evidence");
    add("FORTIFY", S("NOT_APPLICABLE"), "FORTIFY_SOURCE is an ELF/glibc mitigation");
  } else if (report.format === "MACH_O") {
    add("PIE", (sig.pie as BinaryHardeningStatus) ?? S("UNKNOWN"), "Mach-O MH_PIE flag");
    add("NX", sig.stackExec === "NON_EXECUTABLE" ? S("ENABLED") : sig.stackExec === "EXECUTABLE" ? S("DISABLED") : S("UNKNOWN"));
    add("ASLR", (sig.pie as BinaryHardeningStatus) ?? S("UNKNOWN"), "Derived from MH_PIE");
    add("CODE_SIGNING", S("UNKNOWN"), "Mach-O code-signature presence needs tool evidence");
    add("STACK_CANARY", S("UNKNOWN"), "Canary presence needs symbol evidence");
    for (const n of ["RELRO", "FORTIFY", "CFG", "SAFESH"]) add(n, S("NOT_APPLICABLE"), "ELF/PE mitigation families do not apply to Mach-O");
  } else {
    for (const n of ["NX", "PIE", "RELRO", "STACK_CANARY", "FORTIFY", "CFG", "SAFESH", "ASLR", "CODE_SIGNING"]) {
      add(n, S("UNKNOWN"), "Format UNKNOWN — no hardening evidence (§5)");
    }
  }

  // §17 findings — missing RELEVANT mitigations only.
  const findings: NormalizedFinding[] = [];
  const gap = (name: string, ruleId: string, severity: "MEDIUM" | "LOW", remediation: string, status: BinaryHardeningStatus) => {
    findings.push({
      title: `Binary missing ${name} mitigation`,
      description: `Static header analysis of this ${report.format} ${report.kind?.toLowerCase() ?? "binary"} reports ${name} as ${status}. Hardening reduces the impact of memory-safety defects; its absence is a configuration-class weakness, not proof a vulnerability exists (§17).`,
      severity, confidence: 0.9,
      cwe: "CWE-693", // Protection Mechanism Failure
      references: [], sourceTool: source,
      sourceFingerprint: `hardening:${ruleId}:${name}`,
      ruleId,
      remediation,
      binaryFindingType: "BINARY_HARDENING_FINDING",
      binaryComponent: name,
      binaryReachability: "UNKNOWN",
      staticConfidence: "HIGH",
    });
  };
  const byName = new Map(profile.map((p) => [p.name, p.status]));
  const relevant = report.kind !== "OBJECT";
  if (relevant && byName.get("NX") === "DISABLED") gap("NX", "BINARY_NO_NX", "MEDIUM", "Rebuild with a non-executable stack (-Wl,-z,noexecstack / NX_COMPAT).", "DISABLED");
  if (relevant && report.format === "ELF" && byName.get("PIE") === "DISABLED") gap("PIE", "BINARY_NO_PIE", "MEDIUM", "Rebuild as PIE (-fPIE -pie) so ASLR can randomize the executable base.", "DISABLED");
  if (relevant && report.format === "PE" && byName.get("ASLR") === "DISABLED") gap("ASLR", "BINARY_NO_ASLR", "MEDIUM", "Link with /DYNAMICBASE so the image can be ASLR-relocated.", "DISABLED");
  if (relevant && report.format === "ELF" && byName.get("RELRO") === "DISABLED") gap("RELRO", "BINARY_NO_RELRO", "LOW", "Link with -Wl,-z,relro,-z,now for full RELRO.", "DISABLED");
  if (relevant && report.format === "ELF" && byName.get("RELRO") === "PARTIAL") gap("RELRO (partial)", "BINARY_PARTIAL_RELRO", "LOW", "Add -z now (BIND_NOW) to upgrade partial RELRO to full RELRO.", "PARTIAL");
  if (relevant && byName.get("STACK_CANARY") === "DISABLED" && report.format === "ELF") gap("stack canary", "BINARY_NO_CANARY", "LOW", "Compile with -fstack-protector-strong so stack-smashing is detected at runtime.", "DISABLED");
  if (relevant && report.format === "PE" && byName.get("CFG") === "DISABLED") gap("Control Flow Guard", "BINARY_NO_CFG", "LOW", "Compile/link with /guard:cf to validate indirect call targets.", "DISABLED");
  return { profile, findings };
}
