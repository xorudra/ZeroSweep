import { createHash } from "node:crypto";
import type { NormalizedFinding } from "../findings/finding.types";
import { normalizeRepoPath } from "./paths";

/**
 * Source correlation + baselines (Prompt 12 §64–§68, §79, §103).
 *
 * Source fingerprints are LINE-MOVEMENT STABLE: they hash the repository,
 * the file, the rule and a normalized context window around the finding
 * — never the absolute line number — so the same issue at line 50 and
 * line 60 (after unrelated edits elsewhere) is the SAME finding.
 *
 * Cross-tool SAST correlation is conservative (§66): two tools' findings
 * merge only when file, rule-family evidence (shared CWE) AND location
 * context agree. Sharing a CWE alone NEVER merges findings.
 */

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** Normalize a code context window for fingerprinting: collapse
 *  whitespace, strip comments-only variance, lowercase identifiers are
 *  KEPT distinct (renaming a variable is a real change). Secret values
 *  must already be redacted by the caller. */
export function normalizeCodeContext(context: string): string {
  return context.replace(/\s+/g, " ").trim().slice(0, 400);
}

/**
 * Line-independent source fingerprint (§64/§65). Falls back to the
 * tool-provided fingerprint when no context is available (still scoped
 * by repository + file + rule).
 */
export function sourceFingerprint(input: {
  repositoryKey: string;
  filePath: string;
  ruleId: string;
  context?: string;
  toolFingerprint?: string;
}): string {
  const path = normalizeRepoPath(input.filePath) ?? input.filePath;
  const basis = input.context && input.context.trim().length > 0
    ? `ctx:${sha256(normalizeCodeContext(input.context))}`
    : `tool:${input.toolFingerprint ?? "none"}`;
  return sha256(`src|${input.repositoryKey}|${path}|${input.ruleId}|${basis}`);
}

export interface CorrelatedSourceFinding extends NormalizedFinding {
  sources: string[];
  observations: number;
  /** Source fingerprints of every merged member (incl. cross-tool
   *  merges) — persistence maps members back deterministically. */
  memberFingerprints: string[];
}

export interface SourceCorrelationStats {
  input: number;
  canonical: number;
  duplicatesMerged: number;
  crossToolMerges: number;
}

const severityRank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1 };

function mergeInto(target: CorrelatedSourceFinding, f: NormalizedFinding): void {
  target.sources = [...new Set([...target.sources, f.sourceTool])].sort();
  target.observations += 1;
  if (!target.memberFingerprints.includes(f.sourceFingerprint)) target.memberFingerprints.push(f.sourceFingerprint);
  const fMembers = (f as Partial<CorrelatedSourceFinding>).memberFingerprints ?? [];
  for (const m of fMembers) if (!target.memberFingerprints.includes(m)) target.memberFingerprints.push(m);
  if ((severityRank[f.severity] ?? 0) > (severityRank[target.severity] ?? 0)) target.severity = f.severity;
  target.confidence = Math.max(target.confidence, f.confidence);
  target.references = [...new Set([...target.references, ...f.references])];
  target.fixedVersion ??= f.fixedVersion;
  if (f.codeFlow && (!target.codeFlow || f.codeFlow.length > target.codeFlow.length)) target.codeFlow = f.codeFlow;
}

/**
 * Correlate source findings (§66): exact-fingerprint merges first, then
 * conservative cross-tool SAST merges (same file + same CWE + nearby
 * lines + different tools). Dependency findings and secrets are keyed by
 * their own fingerprints and never merge into SAST findings.
 */
export function correlateSourceFindings(
  findings: NormalizedFinding[],
  opts: { lineProximity?: number } = {},
): { findings: CorrelatedSourceFinding[]; stats: SourceCorrelationStats } {
  const proximity = opts.lineProximity ?? 3;
  const canonical: CorrelatedSourceFinding[] = [];
  const byFingerprint = new Map<string, CorrelatedSourceFinding>();
  let duplicatesMerged = 0;
  let crossToolMerges = 0;

  for (const f of findings) {
    const existing = byFingerprint.get(f.sourceFingerprint);
    if (existing) {
      mergeInto(existing, f);
      duplicatesMerged += 1;
      continue;
    }
    const entry: CorrelatedSourceFinding = { ...f, sources: [f.sourceTool], observations: 1, memberFingerprints: [f.sourceFingerprint] };
    byFingerprint.set(f.sourceFingerprint, entry);
    canonical.push(entry);
  }

  // Conservative cross-tool merge (§66): SAST findings only (both carry
  // a ruleId + file + line), different tools, same CWE, lines within
  // proximity. Anything weaker stays a separate finding.
  const merged = new Set<CorrelatedSourceFinding>();
  for (let i = 0; i < canonical.length; i++) {
    const a = canonical[i];
    if (merged.has(a) || !a.ruleId || !a.filePath || a.startLine === undefined || !a.cwe) continue;
    for (let j = i + 1; j < canonical.length; j++) {
      const b = canonical[j];
      if (merged.has(b) || !b.ruleId || !b.filePath || b.startLine === undefined || !b.cwe) continue;
      if (a.sources.some((s) => b.sources.includes(s))) continue; // same tool family already merged by fingerprint
      if (a.filePath !== b.filePath || a.cwe !== b.cwe) continue;
      if (Math.abs(a.startLine - b.startLine) > proximity) continue;
      mergeInto(a, b);
      merged.add(b);
      crossToolMerges += 1;
      duplicatesMerged += 1;
    }
  }

  const result = canonical.filter((f) => !merged.has(f));
  return {
    findings: result,
    stats: { input: findings.length, canonical: result.length, duplicatesMerged, crossToolMerges },
  };
}

/**
 * Baseline classification (§79): compare this snapshot's fingerprints
 * with the previous snapshot's. NEW = not seen before, EXISTING = seen,
 * and the previous set minus the current set = RESOLVED.
 */
export function classifyBaseline(
  current: { sourceFingerprint: string }[],
  previousFingerprints: string[],
): { statuses: Map<string, "NEW" | "EXISTING">; resolved: string[] } {
  const previous = new Set(previousFingerprints);
  const statuses = new Map<string, "NEW" | "EXISTING">();
  const currentSet = new Set<string>();
  for (const f of current) {
    currentSet.add(f.sourceFingerprint);
    statuses.set(f.sourceFingerprint, previous.has(f.sourceFingerprint) ? "EXISTING" : "NEW");
  }
  const resolved = [...previous].filter((fp) => !currentSet.has(fp));
  return { statuses, resolved };
}

/**
 * Source risk signals (§70) — deterministic factors the risk engine
 * records for source findings: internet-facing secrets weigh more than
 * test fixtures, reachable dependencies more than dev-only ones, and a
 * known fixed version lowers remediation friction (not severity).
 */
export function sourceRiskFactors(f: NormalizedFinding): { factor: string; detail: string }[] {
  const factors: { factor: string; detail: string }[] = [];
  if (f.secret) {
    factors.push({ factor: "secret_detected", detail: `Secret type ${f.secret.secretType} detected (metadata only) — rotation required (§43)` });
    if (f.secret.verificationStatus === "VERIFIED_ACTIVE") {
      factors.push({ factor: "secret_verified_active", detail: "The detecting tool reported this credential as verified active" });
    }
  }
  if (f.componentPurl) {
    factors.push({ factor: "dependency_scope", detail: `Dependency scope ${f.dependencyScope ?? "UNKNOWN"}` });
    factors.push({ factor: "reachability", detail: `Reachability ${f.reachability ?? "UNKNOWN"} — static reachability is rarely provable; UNKNOWN is honest (§73)` });
    if (f.fixedVersion) factors.push({ factor: "fix_available", detail: `Fixed version ${f.fixedVersion} reported by a trusted source (§74)` });
  }
  if (f.generatedCode) factors.push({ factor: "generated_code", detail: "Finding is in generated/vendored code — lower default priority (§87)" });
  if (f.reviewStatus === "REVIEW_REQUIRED") factors.push({ factor: "review_required", detail: "Security hotspot — requires human review, not a confirmed vulnerability (§27)" });
  return factors;
}
