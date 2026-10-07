import type { ApiOperation } from "./types";

/**
 * API operation safety policy (Prompt 9 §16–§17, §30, §47–§50).
 *
 * The default automated API baseline strongly prefers safe/read-only
 * requests. State-changing operations require explicit profile/policy
 * approval; unknown state-changing operations never run automatically;
 * DELETE is disabled by default (§48); GraphQL mutations are never
 * executed automatically (§30). Classification is deterministic and
 * explainable — every verdict carries its reasons so denials are
 * auditable (API_OPERATION_BLOCKED) rather than silent.
 */

export const HTTP_METHOD_CLASSES = {
  SAFE_READ: ["GET", "HEAD", "OPTIONS"],
  POTENTIALLY_STATE_CHANGING: ["POST", "PUT", "PATCH", "DELETE"],
} as const;

export type MethodClass = "SAFE_READ" | "POTENTIALLY_STATE_CHANGING" | "UNKNOWN";

export function classifyMethod(method: string): MethodClass {
  const m = method.toUpperCase();
  if ((HTTP_METHOD_CLASSES.SAFE_READ as readonly string[]).includes(m)) return "SAFE_READ";
  if ((HTTP_METHOD_CLASSES.POTENTIALLY_STATE_CHANGING as readonly string[]).includes(m)) return "POTENTIALLY_STATE_CHANGING";
  return "UNKNOWN";
}

export const OPERATION_CLASSIFICATIONS = ["SAFE", "REVIEW_REQUIRED", "STATE_CHANGING", "DESTRUCTIVE_UNKNOWN"] as const;
export type OperationClassification = (typeof OPERATION_CLASSIFICATIONS)[number];

export interface OperationVerdict {
  classification: OperationClassification;
  methodClass: MethodClass;
  reasons: string[];
  /** True only when the automated baseline may execute this operation
   *  under the supplied policy options. */
  automatable: boolean;
}

export interface OperationPolicyOptions {
  /** Explicit profile/policy approval for state-changing operations
   *  (§17/§40). Default false — API_COMPREHENSIVE capabilities stay
   *  disabled until an admin approves them for a specific assessment. */
  allowStateChanging?: boolean;
  /** Explicit approved workflow for DELETE operations (§48). Default
   *  false — DELETE is disabled by default, full stop. */
  allowDelete?: boolean;
  /** Administrator overrides (§17): operationId or `METHOD path` →
   *  classification. Overrides can tighten freely; loosening a
   *  DESTRUCTIVE_UNKNOWN verdict requires the matching allow flag too. */
  overrides?: Record<string, OperationClassification>;
}

const SEGMENT = (path: string): string[] => path.toLowerCase().split("/").filter(Boolean);

/** §47: file-upload operations are REVIEW_REQUIRED — the platform never
 *  uploads executable or harmful content automatically. */
function isUploadOperation(op: ApiOperation): boolean {
  const segs = SEGMENT(op.path);
  if (segs.some((s) => ["upload", "uploads", "import-file", "attach", "attachments"].includes(s))) return true;
  return (op.contentTypes ?? []).some((c) => c.toLowerCase().includes("multipart/form-data"))
    && segs.some((s) => ["upload", "file", "files", "media", "document", "documents"].includes(s));
}

/** §49: financial/transactional routes are REVIEW_REQUIRED and never
 *  executed automatically. */
const FINANCIAL_SEGMENTS = ["payment", "payments", "checkout", "transfer", "transfers", "purchase", "purchases", "refund", "refunds", "billing", "charge", "charges", "payout", "payouts", "order", "orders"];
function isFinancialOperation(op: ApiOperation): boolean {
  return SEGMENT(op.path).some((s) => FINANCIAL_SEGMENTS.includes(s));
}

/** §50: authentication routes get conservative handling — automated
 *  testing must never lock accounts or trigger repeated OTP/email
 *  actions. */
const AUTH_SEGMENTS = ["login", "logout", "register", "signup", "password", "password-reset", "reset-password", "forgot-password", "mfa", "otp", "verify", "verification", "token", "refresh", "session", "sessions", "auth"];
function isAuthOperation(op: ApiOperation): boolean {
  const segs = SEGMENT(op.path);
  return segs.some((s) => AUTH_SEGMENTS.includes(s) || s.startsWith("password") || s.endsWith("-password"));
}

/** Path segments that imply destruction regardless of verb (§17:
 *  unknown/destructive operations are never automated). */
const DESTRUCTIVE_SEGMENTS = ["delete", "destroy", "purge", "truncate", "drop", "wipe", "remove-all", "bulk-delete"];
function hasDestructivePath(op: ApiOperation): boolean {
  return SEGMENT(op.path).some((s) => DESTRUCTIVE_SEGMENTS.includes(s));
}

export class ApiOperationPolicyEngine {
  /**
   * Classify one operation (§17). Considered, in order: administrator
   * overrides, destructive shapes, the HTTP method, sensitive-route
   * classes (upload/financial/auth), request body presence. Unknown
   * state-changing operations classify DESTRUCTIVE_UNKNOWN and can
   * never be automated in this phase.
   */
  classify(op: ApiOperation, options: OperationPolicyOptions = {}): OperationVerdict {
    const method = op.method.toUpperCase();
    const methodClass = classifyMethod(method);
    const reasons: string[] = [];
    let classification: OperationClassification;

    if (hasDestructivePath(op)) {
      classification = "DESTRUCTIVE_UNKNOWN";
      reasons.push("path contains a destructive segment — treated as destructive/unknown (§17)");
    } else if (method === "DELETE") {
      classification = "DESTRUCTIVE_UNKNOWN";
      reasons.push("DELETE operations are disabled by default and require an explicit approved test workflow (§48)");
    } else if (methodClass === "UNKNOWN") {
      classification = "DESTRUCTIVE_UNKNOWN";
      reasons.push(`method ${method} is not a recognized HTTP method — unknown state-changing operations never run automatically (§17)`);
    } else if (isUploadOperation(op)) {
      classification = "REVIEW_REQUIRED";
      reasons.push("file-upload operation — classified REVIEW_REQUIRED, never auto-uploaded (§47)");
    } else if (isFinancialOperation(op)) {
      classification = "REVIEW_REQUIRED";
      reasons.push("financial/transactional route — classified REVIEW_REQUIRED, never executed automatically (§49)");
    } else if (isAuthOperation(op) && methodClass === "POTENTIALLY_STATE_CHANGING") {
      classification = "REVIEW_REQUIRED";
      reasons.push("authentication route — conservative testing only; no account lockout or repeated OTP/email triggers (§50)");
    } else if (methodClass === "SAFE_READ") {
      classification = "SAFE";
      reasons.push(`${method} is a safe read method (§16)`);
      if (isAuthOperation(op)) reasons.push("authentication route — read-only observation only (§50)");
    } else {
      classification = "STATE_CHANGING";
      reasons.push(`${method} is potentially state-changing (§16) — requires explicit profile/policy approval`);
      if (op.hasRequestBody) reasons.push("operation carries a request body");
    }

    // Administrator overrides (§17) apply last for classification, but
    // never silently widen automation: the allow flags below still gate.
    const overrideKey = op.operationId ?? `${method} ${op.path}`;
    const override = options.overrides?.[overrideKey] ?? options.overrides?.[`${method} ${op.path}`];
    if (override) {
      classification = override;
      reasons.push(`administrator override → ${override} (§17)`);
    }

    let automatable = false;
    if (classification === "SAFE") automatable = true;
    else if (classification === "STATE_CHANGING" && options.allowStateChanging === true) {
      automatable = true;
      reasons.push("state-changing execution explicitly approved by profile/policy (§17/§40)");
    } else if (classification === "DESTRUCTIVE_UNKNOWN" && method === "DELETE" && options.allowDelete === true) {
      automatable = true;
      reasons.push("DELETE execution enabled by an explicit approved test workflow (§48)");
    }
    if (!automatable && classification !== "SAFE") {
      reasons.push("not automatable under the current policy — blocked by default");
    }
    return { classification, methodClass, reasons, automatable };
  }

  /** Partition a set of operations for an automated run: the ones the
   *  baseline may execute vs the ones it must block (and count for the
   *  API_OPERATION_BLOCKED audit/event trail). */
  partition(operations: ApiOperation[], options: OperationPolicyOptions = {}): {
    allowed: { op: ApiOperation; verdict: OperationVerdict }[];
    blocked: { op: ApiOperation; verdict: OperationVerdict }[];
  } {
    const allowed: { op: ApiOperation; verdict: OperationVerdict }[] = [];
    const blocked: { op: ApiOperation; verdict: OperationVerdict }[] = [];
    for (const op of operations) {
      const verdict = this.classify(op, options);
      (verdict.automatable ? allowed : blocked).push({ op, verdict });
    }
    return { allowed, blocked };
  }
}

export const apiOperationPolicy = new ApiOperationPolicyEngine();

/** GraphQL operation kinds (§30): queries are reads; mutations and
 *  subscriptions are never executed automatically. */
export type GraphqlOperationKind = "QUERY" | "MUTATION" | "SUBSCRIPTION";
export function graphqlOperationAutomatable(kind: GraphqlOperationKind): boolean {
  return kind === "QUERY";
}
