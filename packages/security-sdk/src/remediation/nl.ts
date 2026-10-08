/**
 * Deterministic natural-language remediation search (Prompt 31 §117).
 * A closed set of question shapes translates to a typed query plan —
 * no AI-generated queries, no free-form parsing of arbitrary text.
 * Unrecognized questions return null and the caller says so honestly.
 */
export type RemediationQueryPlan =
  | { kind: "OVERDUE_KEV" }
  | { kind: "WAITING_VERIFICATION" }
  | { kind: "REGRESSIONS_SINCE"; days: number }
  | { kind: "TEAM_BACKLOG"; priority?: string }
  | { kind: "OVERDUE_ALL" }
  | { kind: "FIX_CLAIMED_UNVERIFIED" }
  | { kind: "SLA_BREACHED" };

export function translateRemediationQuery(text: string): RemediationQueryPlan | null {
  const q = text.toLowerCase().trim();
  if (!q) return null;
  if (q.includes("kev") && (q.includes("overdue") || q.includes("breach") || q.includes("due"))) {
    return { kind: "OVERDUE_KEV" };
  }
  if (q.includes("waiting for verification") || q.includes("awaiting verification") || q.includes("pending verification")) {
    return { kind: "WAITING_VERIFICATION" };
  }
  if (q.includes("regression")) {
    const m = q.match(/(\d+)\s*day/);
    return { kind: "REGRESSIONS_SINCE", days: m ? Number(m[1]) : 30 };
  }
  if ((q.includes("team") || q.includes("owns")) && (q.includes("p1") || q.includes("most") || q.includes("backlog"))) {
    return { kind: "TEAM_BACKLOG", ...(q.includes("p1") ? { priority: "P1" } : {}) };
  }
  if (q.includes("claimed") && (q.includes("not verified") || q.includes("unverified"))) {
    return { kind: "FIX_CLAIMED_UNVERIFIED" };
  }
  if (q.includes("breach")) return { kind: "SLA_BREACHED" };
  if (q.includes("overdue")) return { kind: "OVERDUE_ALL" };
  return null;
}
