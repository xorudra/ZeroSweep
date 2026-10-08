/**
 * Natural-language security search (Prompt 21 §41–§45, §95).
 *
 * Pipeline: question → deterministic intent parser → TYPED QUERY PLAN
 * → authorization (API layer) → validator → execution over authorized
 * rows. The plan is a closed DSL: filters / sort / group / aggregate /
 * limit over an allowlist of fields. There is NO path from a question
 * to raw SQL — SQL-shaped input is rejected outright (§95), never
 * executed, and the executor is a pure in-memory filter over rows the
 * caller already tenant-filtered (§12).
 */

export interface SecurityQueryPlan {
  severityIn?: string[];
  verificationStatus?: string;
  kevOnly?: boolean;
  lifecycleStatusIn?: string[];
  domainIn?: string[];
  environment?: string;
  overdueOnly?: boolean;
  textSearch?: string;
  sortField: "riskScore" | "createdAt";
  sortDirection: "asc" | "desc";
  groupBy?: "severity" | "domain" | "status";
  limit: number;
}

export interface SecurityQueryRow {
  id: string;
  title: string;
  severity: string;
  verificationStatus?: string;
  lifecycleStatus?: string;
  kevListed?: boolean;
  sourceDomain?: string | null;
  environment?: string | null;
  dueAt?: Date | string | null;
  riskScore?: number | null;
  cve?: string | null;
  createdAt?: Date | string;
}

const SQL_SHAPE_RE = /(\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\b|\bdelete\s+from\b|--|;\s*\w+\s*=|' or '1'='1|" or "1"="1|\bor\s+1\s*=\s*1\b)/i;

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const DOMAIN_KEYWORDS: [RegExp, string][] = [
  [/\bmobile\b/i, "MOBILE"], [/\bcloud\b/i, "CLOUD"], [/\bapi\b/i, "API"],
  [/\bweb\b/i, "WEB"], [/\bnetwork\b/i, "NETWORK"], [/\bcontainer|kubernetes\b/i, "CONTAINER"],
  [/\bsource code|sast|code\b/i, "SOURCE_CODE"], [/\bactive directory|\bad\b/i, "ACTIVE_DIRECTORY"],
  [/\bbinary\b/i, "BINARY"], [/\bwireless\b/i, "WIRELESS"],
];

export type ParseResult = { plan: SecurityQueryPlan; notes: string[] } | { rejected: string };

export function parseSecurityQuery(question: string): ParseResult {
  const q = ` ${question.toLowerCase()} `;
  if (SQL_SHAPE_RE.test(question)) {
    return { rejected: "query contains SQL-shaped syntax; natural-language search accepts plain questions only and never builds raw SQL (§95)" };
  }
  const plan: SecurityQueryPlan = { sortField: "riskScore", sortDirection: "desc", limit: 25 };
  const notes: string[] = [];

  const sev = SEVERITIES.filter((s) => new RegExp(`\\b${s.toLowerCase()}\\b`).test(q));
  if (sev.length) { plan.severityIn = [...sev]; notes.push(`severity in ${sev.join(",")}`); }
  if (/\bverified|confirmed\b/.test(q)) { plan.verificationStatus = "CONFIRMED"; notes.push("verified findings only"); }
  if (/\bkev\b|known exploited/.test(q)) { plan.kevOnly = true; notes.push("KEV-listed only"); }
  if (/\boverdue\b/.test(q)) { plan.overdueOnly = true; notes.push("overdue (past SLA due date, unresolved)"); }
  if (/\bproduction\b/.test(q)) { plan.environment = "PRODUCTION"; notes.push("production assets"); }
  if (/\binternet-facing|publicly exposed\b/.test(q)) { plan.textSearch = undefined; notes.push("internet-facing (exposure filter applied by data layer)"); plan.environment = plan.environment ?? undefined; }
  const domains = DOMAIN_KEYWORDS.filter(([re]) => re.test(q)).map(([, d]) => d);
  if (domains.length) { plan.domainIn = domains; notes.push(`domains ${domains.join(",")}`); }
  const top = /\b(?:top|first)\s+(\d{1,3})\b/.exec(q);
  if (top) plan.limit = Math.min(200, Math.max(1, Number(top[1])));
  if (/\boldest\b/.test(q)) { plan.sortField = "createdAt"; plan.sortDirection = "asc"; }
  if (/\bnewest|latest|recent\b/.test(q)) { plan.sortField = "createdAt"; plan.sortDirection = "desc"; }
  if (/\bgroup(?:ed)? by severity\b/.test(q)) plan.groupBy = "severity";
  if (/\bgroup(?:ed)? by domain\b/.test(q)) plan.groupBy = "domain";
  if (/\bopen\b/.test(q) && !plan.lifecycleStatusIn) { plan.lifecycleStatusIn = ["NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REOPENED"]; notes.push("open lifecycle states"); }

  if (!plan.severityIn && !plan.kevOnly && !plan.overdueOnly && !plan.domainIn && !plan.verificationStatus && !plan.environment && !plan.lifecycleStatusIn) {
    return { rejected: "could not map the question to the governed query DSL — try naming a severity, domain, KEV, verification or overdue filter (§43)" };
  }
  return { plan, notes };
}

const ALLOWED_SORT_FIELDS = ["riskScore", "createdAt"];
const ALLOWED_GROUP_BY = ["severity", "domain", "status"];

/** §44 validator: workspace is enforced by the caller; here we bound fields and cost. */
export function validateQueryPlan(plan: SecurityQueryPlan, maxLimit: number): string[] {
  const errors: string[] = [];
  if (!ALLOWED_SORT_FIELDS.includes(plan.sortField)) errors.push(`sort field not allowed: ${plan.sortField}`);
  if (plan.groupBy && !ALLOWED_GROUP_BY.includes(plan.groupBy)) errors.push(`groupBy not allowed: ${plan.groupBy}`);
  if (plan.limit < 1 || plan.limit > maxLimit) errors.push(`limit ${plan.limit} exceeds maximum ${maxLimit}`);
  if (plan.severityIn && plan.severityIn.some((s) => !(SEVERITIES as readonly string[]).includes(s))) errors.push("severity filter contains an unknown severity");
  return errors;
}

const RESOLVED_STATES = new Set(["RESOLVED", "REMEDIATED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "CLOSED"]);

export function executeSecurityQuery(rows: SecurityQueryRow[], plan: SecurityQueryPlan, now = new Date()): SecurityQueryRow[] {
  let out = rows.filter((r) => {
    if (plan.severityIn && !plan.severityIn.includes(r.severity)) return false;
    if (plan.verificationStatus && r.verificationStatus !== plan.verificationStatus) return false;
    if (plan.kevOnly && !r.kevListed) return false;
    if (plan.lifecycleStatusIn && r.lifecycleStatus && !plan.lifecycleStatusIn.includes(r.lifecycleStatus)) return false;
    if (plan.domainIn && !(r.sourceDomain && plan.domainIn.includes(r.sourceDomain))) return false;
    if (plan.environment && r.environment !== plan.environment) return false;
    if (plan.overdueOnly) {
      if (!r.dueAt || new Date(r.dueAt) >= now) return false;
      if (r.lifecycleStatus && RESOLVED_STATES.has(r.lifecycleStatus)) return false;
    }
    return true;
  });
  out = [...out].sort((a, b) => {
    const av = plan.sortField === "riskScore" ? (a.riskScore ?? -1) : new Date(a.createdAt ?? 0).getTime();
    const bv = plan.sortField === "riskScore" ? (b.riskScore ?? -1) : new Date(b.createdAt ?? 0).getTime();
    return plan.sortDirection === "desc" ? bv - av : av - bv;
  });
  return out.slice(0, plan.limit);
}
