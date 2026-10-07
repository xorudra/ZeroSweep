import type { CanonicalFindingView } from "./types";
import { slaStateFor } from "./sla-engine";

/**
 * Executive analytics (Prompt 20 §71–§83/§92).
 *
 * Every number here is computed from stored canonical findings handed
 * to the function — this module invents nothing. Unknown coverage is
 * reported as unknown (§80): a denominator of zero yields null, never
 * a fabricated 100%. Historical trend charts read RiskSnapshot rows
 * (§81); only the current-period series is derived from live state.
 */

const OPEN_LIFECYCLES = new Set(["NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED", "RETEST_PENDING", "REOPENED", "MITIGATED"]);
export function isOpen(f: CanonicalFindingView): boolean {
  return OPEN_LIFECYCLES.has(f.lifecycleStatus);
}

export interface ExecutiveDashboard {
  overallRiskScore: number | null;
  criticalFindings: number;
  highFindings: number;
  verifiedFindings: number;
  kevFindings: number;
  internetFacingFindings: number;
  assetsAtRisk: number;
  slaOverdue: number;
  remediationRate: number | null; // resolved / (resolved + open) — null when nothing has ever been tracked
  topRiskCategories: { category: string; count: number }[];
}

export function executiveDashboard(findings: CanonicalFindingView[], opts: { internetFacingIds?: string[]; now?: Date } = {}): ExecutiveDashboard {
  const now = opts.now ?? new Date();
  const open = findings.filter(isOpen);
  const internet = new Set(opts.internetFacingIds ?? []);
  const resolved = findings.filter((f) => f.lifecycleStatus === "RESOLVED").length;
  const overdue = open.filter((f) => slaStateFor({ dueAt: f.dueAt, lifecycleStatus: f.lifecycleStatus, createdAt: f.firstSeen }, now) === "OVERDUE").length;
  const categories = new Map<string, number>();
  for (const f of open) categories.set(f.category ?? "VULNERABILITY", (categories.get(f.category ?? "VULNERABILITY") ?? 0) + 1);
  return {
    overallRiskScore: open.length ? Math.round(open.reduce((a, f) => a + (f.riskScore ?? 0), 0) / open.length) : null,
    criticalFindings: open.filter((f) => f.severity === "CRITICAL").length,
    highFindings: open.filter((f) => f.severity === "HIGH").length,
    verifiedFindings: findings.filter((f) => f.verificationStatus === "VERIFIED" || f.verificationStatus === "CONFIRMED").length,
    kevFindings: open.filter((f) => f.kevListed).length,
    internetFacingFindings: open.filter((f) => f.id && internet.has(f.id)).length,
    assetsAtRisk: new Set(open.map((f) => f.assetId ?? f.host).filter(Boolean)).size,
    slaOverdue: overdue,
    remediationRate: resolved + open.length === 0 ? null : Math.round((resolved / (resolved + open.length)) * 100) / 100,
    topRiskCategories: [...categories.entries()].map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count).slice(0, 10),
  };
}

export interface SecurityOpsDashboard {
  bySeverity: Record<string, number>;
  byDomain: Record<string, number>;
  byStatus: Record<string, number>;
  newFindings: number;
  reopenedFindings: number;
  retestQueue: number;
}

export function securityOpsDashboard(findings: CanonicalFindingView[], opts: { periodStart?: Date; now?: Date } = {}): SecurityOpsDashboard {
  const periodStart = opts.periodStart ?? new Date(0);
  const count = (fn: (f: CanonicalFindingView) => string | null | undefined) => {
    const out: Record<string, number> = {};
    for (const f of findings) { const k = fn(f); if (k) out[k] = (out[k] ?? 0) + 1; }
    return out;
  };
  return {
    bySeverity: count((f) => f.severity),
    byDomain: count((f) => f.sourceDomain ?? undefined),
    byStatus: count((f) => f.lifecycleStatus),
    newFindings: findings.filter((f) => new Date(f.firstSeen) >= periodStart && f.lifecycleStatus === "NEW").length,
    reopenedFindings: findings.filter((f) => f.lifecycleStatus === "REOPENED" || (f.recurrenceCount ?? 0) > 0).length,
    retestQueue: findings.filter((f) => f.lifecycleStatus === "RETEST_PENDING" || f.lifecycleStatus === "REMEDIATED").length,
  };
}

export interface RemediationDashboard {
  assigned: number;
  unassigned: number;
  overdue: number;
  dueSoon: number;
  remediated: number;
  awaitingRetest: number;
  reopened: number;
  topOwners: { owner: string; open: number }[];
  topTeams: { team: string; open: number }[];
}

export function remediationDashboard(findings: CanonicalFindingView[], opts: { now?: Date } = {}): RemediationDashboard {
  const now = opts.now ?? new Date();
  const open = findings.filter(isOpen);
  const state = (f: CanonicalFindingView) => slaStateFor({ dueAt: f.dueAt, lifecycleStatus: f.lifecycleStatus, createdAt: f.firstSeen }, now);
  const owners = new Map<string, number>();
  const teams = new Map<string, number>();
  for (const f of open) {
    if (f.assignedToId) owners.set(f.assignedToId, (owners.get(f.assignedToId) ?? 0) + 1);
    if (f.assignedToTeam) teams.set(f.assignedToTeam, (teams.get(f.assignedToTeam) ?? 0) + 1);
  }
  const top = (m: Map<string, number>) => [...m.entries()].map(([k, v]) => ({ k, v })).sort((a, b) => b.v - a.v).slice(0, 10);
  return {
    assigned: open.filter((f) => f.assignedToId || f.assignedToTeam).length,
    unassigned: open.filter((f) => !f.assignedToId && !f.assignedToTeam).length,
    overdue: open.filter((f) => state(f) === "OVERDUE").length,
    dueSoon: open.filter((f) => state(f) === "DUE_SOON").length,
    remediated: findings.filter((f) => f.lifecycleStatus === "REMEDIATED").length,
    awaitingRetest: findings.filter((f) => f.lifecycleStatus === "RETEST_PENDING").length,
    reopened: findings.filter((f) => f.lifecycleStatus === "REOPENED").length,
    topOwners: top(owners).map(({ k, v }) => ({ owner: k, open: v })),
    topTeams: top(teams).map(({ k, v }) => ({ team: k, open: v })),
  };
}

export interface AssetRiskDashboard {
  highestRiskAssets: { asset: string; findings: number; maxRisk: number; critical: number }[];
  internetFacingAssets: number;
  assetsWithKev: number;
  assetsWithCritical: number;
  riskByEnvironment: Record<string, number>;
}

export function assetRiskDashboard(findings: CanonicalFindingView[], opts: { internetFacingAssetIds?: string[] } = {}): AssetRiskDashboard {
  const byAsset = new Map<string, { findings: number; maxRisk: number; critical: number; kev: boolean }>();
  const envRisk = new Map<string, { sum: number; n: number }>();
  for (const f of findings.filter(isOpen)) {
    const key = f.assetId ?? f.host;
    if (key) {
      const cur = byAsset.get(key) ?? { findings: 0, maxRisk: 0, critical: 0, kev: false };
      cur.findings++;
      cur.maxRisk = Math.max(cur.maxRisk, f.riskScore ?? 0);
      if (f.severity === "CRITICAL") cur.critical++;
      if (f.kevListed) cur.kev = true;
      byAsset.set(key, cur);
    }
    const env = f.environment ?? "UNSPECIFIED";
    const e = envRisk.get(env) ?? { sum: 0, n: 0 };
    e.sum += f.riskScore ?? 0; e.n++;
    envRisk.set(env, e);
  }
  return {
    highestRiskAssets: [...byAsset.entries()].map(([asset, v]) => ({ asset, ...v })).sort((a, b) => b.maxRisk - a.maxRisk || b.findings - a.findings).slice(0, 20).map(({ kev: _kev, ...rest }) => rest),
    internetFacingAssets: (opts.internetFacingAssetIds ?? []).length,
    assetsWithKev: [...byAsset.values()].filter((v) => v.kev).length,
    assetsWithCritical: [...byAsset.values()].filter((v) => v.critical > 0).length,
    riskByEnvironment: Object.fromEntries([...envRisk.entries()].map(([k, v]) => [k, v.n ? Math.round(v.sum / v.n) : 0])),
  };
}

// ---------------- Trends & time metrics (§76–§79) ----------------

export interface TrendPoint { date: string; newFindings: number; resolvedFindings: number; criticalHighBacklog: number; slaOverdue: number }

export function trendSeries(findings: CanonicalFindingView[], days: number, now: Date = new Date()): TrendPoint[] {
  const points: TrendPoint[] = [];
  for (let d = days - 1; d >= 0; d--) {
    const dayStart = new Date(now.getTime() - d * 86400_000);
    const dayEnd = new Date(dayStart.getTime() + 86400_000);
    const inDay = (v: Date | string | null | undefined) => { if (!v) return false; const t = new Date(v); return t >= dayStart && t < dayEnd; };
    points.push({
      date: dayStart.toISOString().slice(0, 10),
      newFindings: findings.filter((f) => inDay(f.firstSeen)).length,
      resolvedFindings: findings.filter((f) => inDay(f.resolvedAt)).length,
      criticalHighBacklog: findings.filter((f) => isOpen(f) && (f.severity === "CRITICAL" || f.severity === "HIGH") && new Date(f.firstSeen) < dayEnd).length,
      slaOverdue: findings.filter((f) => isOpen(f) && f.dueAt && new Date(f.dueAt) < dayEnd).length,
    });
  }
  return points;
}

function hoursBetween(a: Date | string, b: Date | string): number {
  return (new Date(b).getTime() - new Date(a).getTime()) / 3600_000;
}

function mean(values: number[]): number | null {
  return values.length ? Math.round((values.reduce((x, y) => x + y, 0) / values.length) * 10) / 10 : null;
}

function groupMean<T extends CanonicalFindingView>(findings: T[], key: (f: T) => string | undefined, value: (f: T) => number | null): Record<string, number | null> {
  const groups = new Map<string, number[]>();
  for (const f of findings) {
    const k = key(f); const v = value(f);
    if (!k || v === null) continue;
    groups.set(k, [...(groups.get(k) ?? []), v]);
  }
  return Object.fromEntries([...groups.entries()].map(([k, v]) => [k, mean(v)]));
}

/** §77 MTTR (hours) overall + by severity/priority/team/domain/environment. */
export function meanTimeToRemediate(findings: CanonicalFindingView[]) {
  const resolved = findings.filter((f) => f.resolvedAt);
  const value = (f: CanonicalFindingView) => (f.resolvedAt ? hoursBetween(f.firstSeen, f.resolvedAt) : null);
  return {
    overallHours: mean(resolved.map((f) => value(f)!).filter((v) => v >= 0)),
    bySeverity: groupMean(resolved, (f) => f.severity, value),
    byPriority: groupMean(resolved, (f) => f.priority ?? undefined, value),
    byTeam: groupMean(resolved, (f) => f.assignedToTeam ?? undefined, value),
    byDomain: groupMean(resolved, (f) => f.sourceDomain ?? undefined, value),
    byEnvironment: groupMean(resolved, (f) => f.environment ?? undefined, value),
  };
}

/** §78 MTTT (hours): firstSeen → first triage (approximated by history-free
 *  stored timestamps: findings that left NEW). Callers with history data
 *  pass triagedAt via the view's optional field. */
export function meanTimeToTriage(findings: (CanonicalFindingView & { triagedAt?: Date | string | null })[]) {
  const triaged = findings.filter((f) => f.triagedAt);
  return {
    overallHours: mean(triaged.map((f) => hoursBetween(f.firstSeen, f.triagedAt!)).filter((v) => v >= 0)),
    bySeverity: groupMean(triaged, (f) => f.severity, (f) => (f.triagedAt ? hoursBetween(f.firstSeen, f.triagedAt) : null)),
    byDomain: groupMean(triaged, (f) => f.sourceDomain ?? undefined, (f) => (f.triagedAt ? hoursBetween(f.firstSeen, f.triagedAt) : null)),
  };
}

/** §79: resolved findings that later reopened / total resolved. */
export function reopenRate(findings: CanonicalFindingView[]): { rate: number | null; reopened: number; resolvedEver: number } {
  const resolvedEver = findings.filter((f) => f.resolvedAt || f.lifecycleStatus === "RESOLVED").length;
  const reopened = findings.filter((f) => (f.recurrenceCount ?? 0) > 0 || f.lifecycleStatus === "REOPENED").length;
  return { rate: resolvedEver === 0 ? null : Math.round((reopened / resolvedEver) * 100) / 100, reopened, resolvedEver };
}

// ---------------- Coverage (§80) ----------------

export interface CoverageInput {
  assetsDiscovered: number;
  assetsScanned: number;
  repositoriesScanned: number;
  repositoriesKnown?: number;
  cloudAccountsAssessed: number;
  cloudAccountsKnown?: number;
  clustersAssessed: number;
  clustersKnown?: number;
  mobileBuildsAssessed: number;
  mobileBuildsKnown?: number;
  wirelessEnvironmentsAssessed: number;
  wirelessEnvironmentsKnown?: number;
}

export interface CoverageResult {
  assetsScannedPct: number | null;
  repositoriesPct: number | null;
  cloudAccountsPct: number | null;
  clustersPct: number | null;
  mobileBuildsPct: number | null;
  wirelessEnvironmentsPct: number | null;
  counts: CoverageInput;
  note: string;
}

function pct(done: number, known?: number): number | null {
  if (known === undefined || known === 0) return null; // unknown — never presented as 100% (§80)
  return Math.round((done / known) * 1000) / 10;
}

export function securityCoverage(input: CoverageInput): CoverageResult {
  return {
    assetsScannedPct: pct(input.assetsScanned, input.assetsDiscovered),
    repositoriesPct: pct(input.repositoriesScanned, input.repositoriesKnown),
    cloudAccountsPct: pct(input.cloudAccountsAssessed, input.cloudAccountsKnown),
    clustersPct: pct(input.clustersAssessed, input.clustersKnown),
    mobileBuildsPct: pct(input.mobileBuildsAssessed, input.mobileBuildsKnown),
    wirelessEnvironmentsPct: pct(input.wirelessEnvironmentsAssessed, input.wirelessEnvironmentsKnown),
    counts: input,
    note: "Percentages are null where the denominator is unknown — unknown coverage is never presented as 100% (§80).",
  };
}

// ---------------- Filters, search, metrics (§82/§83/§92) ----------------

export interface FindingFilter {
  workspaceId?: string;
  dateFrom?: Date;
  dateTo?: Date;
  environment?: string;
  assetId?: string;
  domain?: string;
  severity?: string;
  priority?: string;
  status?: string;
  verification?: string;
  owner?: string;
  team?: string;
  cve?: string;
  cwe?: string;
  kev?: boolean;
  slaState?: string;
}

export function matchesFilter(f: CanonicalFindingView, filter: FindingFilter, now: Date = new Date()): boolean {
  if (filter.workspaceId && f.workspaceId !== filter.workspaceId) return false;
  if (filter.dateFrom && new Date(f.firstSeen) < filter.dateFrom) return false;
  if (filter.dateTo && new Date(f.firstSeen) > filter.dateTo) return false;
  if (filter.environment && f.environment !== filter.environment) return false;
  if (filter.assetId && f.assetId !== filter.assetId) return false;
  if (filter.domain && f.sourceDomain !== filter.domain) return false;
  if (filter.severity && f.severity !== filter.severity) return false;
  if (filter.priority && f.priority !== filter.priority) return false;
  if (filter.status && f.lifecycleStatus !== filter.status) return false;
  if (filter.verification && f.verificationStatus !== filter.verification) return false;
  if (filter.owner && f.assignedToId !== filter.owner) return false;
  if (filter.team && f.assignedToTeam !== filter.team) return false;
  if (filter.cve && (f.cve ?? "").toUpperCase() !== filter.cve.toUpperCase()) return false;
  if (filter.cwe && (f.cwe ?? "").toUpperCase() !== filter.cwe.toUpperCase()) return false;
  if (filter.kev !== undefined && !!f.kevListed !== filter.kev) return false;
  if (filter.slaState && slaStateFor({ dueAt: f.dueAt, lifecycleStatus: f.lifecycleStatus, createdAt: f.firstSeen }, now) !== filter.slaState) return false;
  return true;
}

export interface SearchCorpus {
  findings: CanonicalFindingView[];
  assets: { id: string; host: string; label?: string }[];
  repositories: { id: string; name: string }[];
  cloudResources: { id: string; name: string }[];
  mobileApps: { id: string; name: string }[];
  binaryHashes: { id: string; sha256: string }[];
}

export interface SearchHit { kind: "FINDING" | "ASSET" | "REPOSITORY" | "CLOUD_RESOURCE" | "MOBILE_APP" | "BINARY"; id: string; label: string }

/** §83: unified search across findings (id/CVE/CWE), assets, URLs,
 *  repositories, cloud resources, mobile apps and binary hashes. The
 *  corpus handed in is already tenant-scoped by the caller. */
export function globalSearch(corpus: SearchCorpus, query: string, limit = 50): SearchHit[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hits: SearchHit[] = [];
  for (const f of corpus.findings) {
    if (f.id.toLowerCase().includes(q) || (f.cve ?? "").toLowerCase().includes(q) || (f.cwe ?? "").toLowerCase().includes(q) || f.title.toLowerCase().includes(q) || (f.endpoint ?? "").toLowerCase().includes(q)) {
      hits.push({ kind: "FINDING", id: f.id, label: f.title });
    }
  }
  for (const a of corpus.assets) if (a.host.toLowerCase().includes(q) || a.id.toLowerCase().includes(q)) hits.push({ kind: "ASSET", id: a.id, label: a.label ?? a.host });
  for (const r of corpus.repositories) if (r.name.toLowerCase().includes(q)) hits.push({ kind: "REPOSITORY", id: r.id, label: r.name });
  for (const c of corpus.cloudResources) if (c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q)) hits.push({ kind: "CLOUD_RESOURCE", id: c.id, label: c.name });
  for (const m of corpus.mobileApps) if (m.name.toLowerCase().includes(q)) hits.push({ kind: "MOBILE_APP", id: m.id, label: m.name });
  for (const b of corpus.binaryHashes) if (b.sha256.toLowerCase().includes(q)) hits.push({ kind: "BINARY", id: b.id, label: b.sha256 });
  return hits.slice(0, limit);
}

/** §92 observability counters for the unified layer. */
export function vmObservability(input: {
  findings: CanonicalFindingView[];
  observations: number;
  correlations: number;
  imports: number;
  syncFailures: number;
  retests: number;
  reportsGenerated: number;
  reportFailures: number;
  now?: Date;
}): Record<string, number | null> {
  const now = input.now ?? new Date();
  const canonical = input.findings.filter((f) => f.lifecycleStatus !== "DUPLICATE").length;
  const mttr = meanTimeToRemediate(input.findings).overallHours;
  const rr = reopenRate(input.findings);
  return {
    findings: input.findings.length,
    canonicalFindings: canonical,
    observations: input.observations,
    dedupRatio: input.observations === 0 ? null : Math.round((input.observations / Math.max(1, canonical)) * 100) / 100,
    correlationCount: input.correlations,
    importCount: input.imports,
    syncFailures: input.syncFailures,
    slaOverdue: input.findings.filter((f) => isOpen(f) && slaStateFor({ dueAt: f.dueAt, lifecycleStatus: f.lifecycleStatus, createdAt: f.firstSeen }, now) === "OVERDUE").length,
    retests: input.retests,
    reportsGenerated: input.reportsGenerated,
    reportFailures: input.reportFailures,
    mttrHours: mttr,
    reopenRate: rr.rate,
  };
}
