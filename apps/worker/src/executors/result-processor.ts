import { findingFingerprint, ScopeMatcher, type NormalizedSecurityResult } from "@dsrclone/security-sdk";
import type { ScopeRules } from "@dsrclone/validation";

/**
 * Result processing (Prompt 4 §32–§37): normalized results — and ONLY
 * normalized results — become persistence records. Tool-specific output never
 * leaks into core logic. Discovered assets are canonicalized, deduplicated and
 * scope-checked; out-of-scope assets are kept for visibility with an
 * OUT_OF_SCOPE verdict and never become scan targets.
 */
export interface ProcessedAsset {
  host: string;
  ip?: string;
  type: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE" | "PENDING_REVIEW";
}

export interface ProcessedFinding {
  title: string;
  description: string;
  severity: string;
  confidence: number;
  host?: string;
  endpoint?: string;
  fingerprint: string;
  isMock: boolean;
  sourceTool: string;
  toolExecutionId: string;
  evidenceSummary: string;
}

export interface ProcessedResult {
  assets: ProcessedAsset[];
  endpoints: { url: string; method: string }[];
  findings: ProcessedFinding[];
  isMock: boolean;
}

export function canonicalHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

export function processNormalizedResult(
  result: NormalizedSecurityResult,
  ctx: { scopeRules: ScopeRules; toolExecutionId: string },
): ProcessedResult {
  const matcher = new ScopeMatcher(ctx.scopeRules);
  const seen = new Set<string>();
  const assets: ProcessedAsset[] = [];
  for (const asset of result.assets) {
    const host = canonicalHost(asset.host);
    if (!host || seen.has(host)) continue;
    seen.add(host);
    const verdict = matcher.isDiscoveredAssetInScope(host);
    assets.push({
      host,
      ip: asset.ip,
      type: asset.type,
      scopeStatus: verdict.allowed ? "IN_SCOPE" : "OUT_OF_SCOPE",
    });
  }
  const findings: ProcessedFinding[] = result.findings.map((f) => ({
    title: f.title,
    description: f.description,
    severity: f.severity,
    confidence: f.confidence,
    host: f.host,
    endpoint: f.endpoint,
    fingerprint: f.sourceFingerprint && f.sourceFingerprint !== "mock-fixture"
      ? f.sourceFingerprint
      : findingFingerprint({ toolFamily: f.sourceTool, asset: f.host ?? "unknown", endpoint: f.endpoint, vulnClass: f.title }),
    isMock: result.mock,
    sourceTool: f.sourceTool,
    toolExecutionId: ctx.toolExecutionId,
    evidenceSummary: f.evidence ?? "",
  }));
  return {
    assets,
    endpoints: result.endpoints.map((e) => ({ url: e.url, method: e.method ?? "GET" })),
    findings,
    isMock: result.mock,
  };
}

/** Deterministic correlation grouping (Prompt 4 §36) — no AI, original
 *  evidence is preserved on each finding; groups share a correlation key. */
export function correlationKey(f: { fingerprint: string; host?: string; endpoint?: string; title: string }): string {
  return f.fingerprint;
}

export function groupFindings(findings: ProcessedFinding[]): Map<string, ProcessedFinding[]> {
  const groups = new Map<string, ProcessedFinding[]>();
  for (const f of findings) {
    const key = correlationKey(f);
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  return groups;
}

/** Deterministic fixture risk scoring (Prompt 4 §37) — severity weights only,
 *  no fabricated external threat intelligence. */
const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 40, HIGH: 25, MEDIUM: 12, LOW: 5, INFORMATIONAL: 1 };
export function fixtureRiskScore(findings: ProcessedFinding[]): number {
  const raw = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0) * f.confidence, 0);
  return Math.min(100, Math.round(raw));
}
