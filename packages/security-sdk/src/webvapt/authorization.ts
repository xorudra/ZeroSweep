/**
 * Authorization (IDOR/BOLA) testing + business-logic scenarios
 * (Prompt 32 §97–§104).
 *
 * This is a FOUNDATION, not an enumerator: tests run only against
 * user-provided, authorized test identities and KNOWN resource
 * fixtures (§98). The platform never enumerates unrelated users or
 * resources, never sprays passwords (§104 — Hydra/Medusa/credential
 * stuffing are forbidden modules, structurally absent), and a
 * mismatch becomes a CANDIDATE finding that still needs evidence and
 * governed verification (§100).
 */

export type AccessExpectation = "ALLOW" | "DENY";
export type AccessObservation = "ALLOW" | "DENY" | "NOT_TESTED";

export interface AuthorizationMatrixRow {
  identityA: string;
  identityB?: string;
  role: string;
  /** Resource FIXTURE identifier (a controlled test object, §98). */
  resource: string;
  expectedAccess: AccessExpectation;
  observedAccess: AccessObservation;
}

export interface AuthorizationCandidate {
  /** Index of the matrix row that produced this candidate. */
  rowIndex: number;
  title: string;
  cwe: string;
  category: "AUTHORIZATION";
  confidence: "LOW" | "MEDIUM" | "HIGH";
  evidence: string;
  resource: string;
  role: string;
}

/** §100: expected ≠ observed ⇒ candidate finding (never auto-confirmed). */
export function evaluateAuthorizationMatrix(rows: AuthorizationMatrixRow[]): { candidates: AuthorizationCandidate[]; matches: number; untested: number } {
  const candidates: AuthorizationCandidate[] = [];
  let matches = 0;
  let untested = 0;
  rows.forEach((row, rowIndex) => {
    if (row.observedAccess === "NOT_TESTED") { untested += 1; return; }
    if (row.observedAccess === row.expectedAccess) { matches += 1; return; }
    const privilegeEscalation = row.expectedAccess === "DENY" && row.observedAccess === "ALLOW";
    candidates.push({
      rowIndex,
      title: privilegeEscalation
        ? `Broken access control: role ${row.role} could access fixture resource ${row.resource} (expected DENY)`
        : `Access control inconsistency: role ${row.role} denied fixture resource ${row.resource} (expected ALLOW)`,
      cwe: "CWE-862",
      category: "AUTHORIZATION",
      confidence: privilegeEscalation ? "HIGH" : "MEDIUM",
      evidence: `matrix row: identityA=${row.identityA}${row.identityB ? ` identityB=${row.identityB}` : ""} role=${row.role} resource=${row.resource} expected=${row.expectedAccess} observed=${row.observedAccess} — candidate requiring evidence review (§100)`,
      resource: row.resource,
      role: row.role,
    });
  });
  return { candidates, matches, untested };
}

/** §98: fixture discipline — resource identifiers must be templates or
 *  explicitly-marked fixtures, never raw production object ids. */
export function isFixtureResourceIdentifier(resource: string): boolean {
  return /\{[^}]+\}/.test(resource) || /^fixture[:/]/i.test(resource) || /^test[:/]/i.test(resource);
}

export function validateMatrixRows(rows: AuthorizationMatrixRow[]): string[] {
  const problems: string[] = [];
  for (const row of rows) {
    if (!isFixtureResourceIdentifier(row.resource)) {
      problems.push(`resource '${row.resource}' is not a fixture/template identifier — broad enumeration of real objects is forbidden (§98)`);
    }
    if (!row.identityA) problems.push("identityA is required — tests use user-provided authorized identities only (§97)");
  }
  return problems;
}

/* ------------------------- business logic (§101/§102) ------------------------- */

export interface BusinessLogicScenarioInput {
  name: string;
  preconditions: string;
  authorizedIdentities: string[];
  /** Safe steps only: each step is a human-authored description. */
  safeSteps: string[];
  expectedBehavior: string;
}

const DESTRUCTIVE_STEP = /\b(delete|destroy|drop|truncate|transfer\s+funds|refund|charge|purchase|shell|exec)\b/i;

/**
 * §101: the framework stores HUMAN-DEFINED scenarios. A step that
 * describes a destructive or state-changing action is rejected at
 * intake — the scenario runner performs governed reads/comparisons,
 * and anything state-changing belongs to the Prompt 16 validation
 * framework with its own plan-hash approval.
 */
export function validateBusinessLogicScenario(input: BusinessLogicScenarioInput): string[] {
  const problems: string[] = [];
  if (!input.name.trim()) problems.push("scenario name is required");
  if (input.authorizedIdentities.length === 0) problems.push("at least one authorized identity is required (§102)");
  if (input.safeSteps.length === 0) problems.push("at least one safe step is required (§102)");
  for (const step of input.safeSteps) {
    if (DESTRUCTIVE_STEP.test(step)) problems.push(`step '${step.slice(0, 60)}' describes a destructive/state-changing action — not a safe step (§101)`);
  }
  if (!input.expectedBehavior.trim()) problems.push("expected behavior is required — a scenario without an expectation cannot be evaluated (§102)");
  return problems;
}

/* ------------------------- §103/§104 guardrails ------------------------- */

/** §104: password-attack tooling is forbidden in web/API orchestration. */
export const FORBIDDEN_PASSWORD_MODULES = ["hydra", "medusa", "ncrack", "patator"] as const;

export function isForbiddenPasswordModule(slug: string): boolean {
  return (FORBIDDEN_PASSWORD_MODULES as readonly string[]).includes(slug.toLowerCase());
}

/**
 * §103: rate-limit ANALYSIS is a bounded observation plan — a small,
 * fixed number of unauthenticated requests against ONE endpoint. It is
 * never a credential-stuffing or volume tool.
 */
export const RATE_LIMIT_ANALYSIS_BOUNDS = { maxRequests: 20, minIntervalMs: 250, singleEndpoint: true } as const;

export function clampRateLimitAnalysis(requested: { requests?: number; intervalMs?: number }): { requests: number; intervalMs: number; clamped: boolean } {
  const requests = Math.min(RATE_LIMIT_ANALYSIS_BOUNDS.maxRequests, Math.max(1, Math.floor(requested.requests ?? 10)));
  const intervalMs = Math.max(RATE_LIMIT_ANALYSIS_BOUNDS.minIntervalMs, Math.floor(requested.intervalMs ?? 500));
  return { requests, intervalMs, clamped: requests !== (requested.requests ?? 10) || intervalMs !== (requested.intervalMs ?? 500) };
}
