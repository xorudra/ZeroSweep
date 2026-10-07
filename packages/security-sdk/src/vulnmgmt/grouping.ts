/**
 * Remediation grouping (Prompt 11 §53–§54). Deterministic root-cause
 * grouping: findings that can likely be fixed together share a group key
 * derived from stable attributes (CVE → configuration class → CWE →
 * technology). No AI grouping is ever the source of truth (§54).
 */

export interface GroupableFinding {
  id: string;
  cve?: string | null;
  cwe?: string | null;
  vulnClass?: string | null;
  host?: string | null;
  title: string;
  lifecycleStatus: string;
  priority?: string | null;
  severity: string;
}

export interface RemediationGroup {
  key: string;
  kind: "CVE" | "CONFIG_CLASS" | "CWE" | "TITLE";
  label: string;
  findingIds: string[];
  openCount: number;
  worstPriority?: string;
  hosts: string[];
}

const PRIORITY_RANK: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
const CLOSED = new Set(["RESOLVED", "FALSE_POSITIVE"]);

/** Configuration classes (§53): findings sharing a vulnClass are one
 *  configuration fix (same TLS policy, same missing-header policy, …). */
export function remediationGroupKey(f: GroupableFinding): { key: string; kind: RemediationGroup["kind"]; label: string } {
  if (f.cve) return { key: `cve:${f.cve.toUpperCase()}`, kind: "CVE", label: `${f.cve.toUpperCase()} — patch / upgrade the affected component` };
  if (f.vulnClass) return { key: `class:${f.vulnClass}`, kind: "CONFIG_CLASS", label: `${f.vulnClass} — one configuration fix` };
  if (f.cwe) return { key: `cwe:${f.cwe.toUpperCase()}`, kind: "CWE", label: `${f.cwe.toUpperCase()} — shared root cause` };
  return { key: `title:${f.title.toLowerCase()}`, kind: "TITLE", label: f.title };
}

export function groupFindingsForRemediation(findings: GroupableFinding[]): RemediationGroup[] {
  const groups = new Map<string, RemediationGroup>();
  for (const f of findings) {
    const { key, kind, label } = remediationGroupKey(f);
    let g = groups.get(key);
    if (!g) { g = { key, kind, label, findingIds: [], openCount: 0, hosts: [] }; groups.set(key, g); }
    g.findingIds.push(f.id);
    if (!CLOSED.has(f.lifecycleStatus)) g.openCount++;
    if (f.host && !g.hosts.includes(f.host)) g.hosts.push(f.host);
    if (f.priority && (g.worstPriority === undefined || (PRIORITY_RANK[f.priority] ?? 9) < (PRIORITY_RANK[g.worstPriority] ?? 9))) {
      g.worstPriority = f.priority;
    }
  }
  return [...groups.values()]
    .filter((g) => g.findingIds.length > 0)
    .sort((a, b) => (PRIORITY_RANK[a.worstPriority ?? "P4"] ?? 9) - (PRIORITY_RANK[b.worstPriority ?? "P4"] ?? 9) || b.findingIds.length - a.findingIds.length);
}
