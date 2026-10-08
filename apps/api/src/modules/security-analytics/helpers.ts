import type { DslRecord } from "@dsrclone/security-sdk";

/**
 * Shared record builders: turn tenant-scoped rows into the flat
 * records the governed DSL evaluates (§35/§36). The DSL never sees a
 * database handle — only these plain records.
 */

export const RESOLVED_LIFECYCLES = new Set(["RESOLVED", "REMEDIATED", "CLOSED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "MITIGATED"]);

export function docToDslRecord(doc: {
  documentType: string; searchableText: string; classification: string;
  severity?: string | null; riskScore?: number | null; facets?: unknown; updatedAt?: Date | string;
}): DslRecord {
  const f = (doc.facets ?? {}) as Record<string, unknown>;
  return {
    type: doc.documentType.toLowerCase(),
    severity: (doc.severity ?? (f.severity as string) ?? null)?.toLowerCase() ?? null,
    status: ((f.status as string) ?? null)?.toLowerCase() ?? null,
    lifecycle_status: ((f.lifecycleStatus as string) ?? null)?.toLowerCase() ?? null,
    priority: ((f.priority as string) ?? null)?.toLowerCase() ?? null,
    kev: typeof f.kev === "boolean" ? f.kev : null,
    internet_exposed: typeof f.internetExposed === "boolean" ? f.internetExposed : null,
    verified: typeof f.verified === "boolean" ? f.verified : null,
    technology: (f.technologies as string[]) ?? null,
    cve: ((f.cve as string) ?? null)?.toLowerCase() ?? null,
    cwe: ((f.cwe as string) ?? null)?.toLowerCase() ?? null,
    risk: doc.riskScore ?? null,
    source: ((f.source as string) ?? null)?.toLowerCase() ?? null,
    repository: ((f.repository as string) ?? null)?.toLowerCase() ?? null,
    control: ((f.control as string) ?? null)?.toLowerCase() ?? null,
    framework: ((f.framework as string) ?? null)?.toLowerCase() ?? null,
    classification: doc.classification.toLowerCase(),
    asset: ((f.assetHost as string) ?? null)?.toLowerCase() ?? null,
    event_type: ((f.eventType as string) ?? null)?.toLowerCase() ?? null,
    _text: doc.searchableText,
    _time: doc.updatedAt ? new Date(doc.updatedAt).toISOString() : undefined,
  };
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
export function severityRank(s: string | null | undefined): number {
  return s ? (SEVERITY_RANK[s] ?? 0) : 0;
}

const CRITICALITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNSPECIFIED: 0 };
export function criticalityRank(c: string | null | undefined): number {
  return c ? (CRITICALITY_RANK[c] ?? 0) : 0;
}

/** CSV cell escaping — values are data, never formula/markup (§102 + P20 discipline). */
export function csvCell(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  const guarded = /^[=+\-@]/.test(s) ? `'${s}` : s;
  return `"${guarded.replace(/"/g, '""')}"`;
}
