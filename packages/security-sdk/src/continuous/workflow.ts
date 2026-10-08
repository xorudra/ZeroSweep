import { createHash } from "node:crypto";

/**
 * Security workflow engine core (Prompt 22 §56–§64).
 *
 * event → typed conditions → approved SAFE actions. There is NO
 * arbitrary workflow code: users cannot upload JavaScript, Python or
 * shell as actions (§61), the DSL validator rejects any code-shaped
 * key anywhere in the document, and every action is one of a closed
 * typed vocabulary (§60). Loop protection (§63) combines execution
 * depth, event lineage and dedup keys.
 */

export const WORKFLOW_TRIGGERS = [
  "FINDING_CREATED", "FINDING_VERIFIED", "FINDING_REOPENED", "KEV_DETECTED",
  "SLA_DUE_SOON", "SLA_OVERDUE", "NEW_PUBLIC_ASSET", "RISK_INCREASED",
  "SCAN_FAILED", "REPORT_READY",
] as const;
export type WorkflowTrigger = (typeof WORKFLOW_TRIGGERS)[number];

export const WORKFLOW_ACTIONS = [
  "CREATE_NOTIFICATION", "ASSIGN_FINDING", "SET_PRIORITY",
  "REQUEST_SAFE_RETEST", "CREATE_REPORT_DRAFT", "CREATE_ANALYST_TASK", "ADD_TAG",
] as const;
export type WorkflowActionType = (typeof WORKFLOW_ACTIONS)[number];

export const CONDITION_FIELDS = [
  "severity", "priority", "environment", "assetType", "verification", "kev", "riskScore", "owner", "tag", "domain",
] as const;
export type ConditionField = (typeof CONDITION_FIELDS)[number];

export const CONDITION_OPERATORS = ["eq", "neq", "in", "gte", "lte", "contains"] as const;
export type ConditionOperator = (typeof CONDITION_OPERATORS)[number];

export interface WorkflowCondition {
  field: ConditionField;
  operator: ConditionOperator;
  value: unknown;
}

export interface WorkflowAction {
  type: WorkflowActionType;
  /** Typed parameters only — validated per action type below. */
  params?: Record<string, string | number | boolean>;
}

export interface SecurityWorkflowDsl {
  trigger: WorkflowTrigger;
  conditions: WorkflowCondition[];
  actions: WorkflowAction[];
}

const CODE_SHAPED_KEYS = new Set([
  "script", "code", "command", "shell", "python", "javascript", "js", "eval",
  "exec", "function", "webhook", "url", "http", "sql", "query",
]);

function scanForCodeKeys(value: unknown, path: string, errors: string[]): void {
  if (Array.isArray(value)) { value.forEach((v, i) => scanForCodeKeys(v, `${path}[${i}]`, errors)); return; }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (CODE_SHAPED_KEYS.has(k.toLowerCase())) {
        errors.push(`${path}.${k}: arbitrary code/command fields are prohibited in workflow definitions (§61)`);
      }
      scanForCodeKeys(v, `${path}.${k}`, errors);
    }
  }
}

const ACTION_PARAM_KEYS: Record<WorkflowActionType, Set<string>> = {
  CREATE_NOTIFICATION: new Set(["channel", "template"]),
  ASSIGN_FINDING: new Set(["assigneeId", "team"]),
  SET_PRIORITY: new Set(["priority"]),
  REQUEST_SAFE_RETEST: new Set(["reason"]),
  CREATE_REPORT_DRAFT: new Set(["reportType", "title"]),
  CREATE_ANALYST_TASK: new Set(["title", "assigneeId", "team"]),
  ADD_TAG: new Set(["tag"]),
};

const SETTABLE_PRIORITIES = new Set(["P0", "P1", "P2", "P3", "P4"]);

export function validateWorkflowDsl(dsl: unknown): { ok: boolean; errors: string[]; value?: SecurityWorkflowDsl } {
  const errors: string[] = [];
  scanForCodeKeys(dsl, "$", errors);
  if (!dsl || typeof dsl !== "object") return { ok: false, errors: ["workflow definition must be an object"] };
  const doc = dsl as Record<string, unknown>;
  const allowedTop = new Set(["trigger", "conditions", "actions", "name"]);
  for (const k of Object.keys(doc)) if (!allowedTop.has(k)) errors.push(`$.${k}: unknown top-level field`);
  if (!(WORKFLOW_TRIGGERS as readonly string[]).includes(String(doc.trigger))) {
    errors.push(`trigger must be one of ${WORKFLOW_TRIGGERS.join(", ")}`);
  }
  const conditions = Array.isArray(doc.conditions) ? doc.conditions : [];
  if (!Array.isArray(doc.conditions)) errors.push("conditions must be an array");
  conditions.forEach((c, i) => {
    const cond = c as Record<string, unknown>;
    if (!(CONDITION_FIELDS as readonly string[]).includes(String(cond.field))) errors.push(`conditions[${i}].field is not a typed condition field (§59)`);
    if (!(CONDITION_OPERATORS as readonly string[]).includes(String(cond.operator))) errors.push(`conditions[${i}].operator is not supported`);
    if (cond.value === undefined) errors.push(`conditions[${i}].value is required`);
  });
  const actions = Array.isArray(doc.actions) ? doc.actions : [];
  if (!Array.isArray(doc.actions) || actions.length === 0) errors.push("actions must be a non-empty array of typed actions (§60)");
  actions.forEach((a, i) => {
    const action = a as Record<string, unknown>;
    if (!(WORKFLOW_ACTIONS as readonly string[]).includes(String(action.type))) {
      errors.push(`actions[${i}].type is not an approved safe action (§60)`);
      return;
    }
    const params = (action.params ?? {}) as Record<string, unknown>;
    const allowed = ACTION_PARAM_KEYS[action.type as WorkflowActionType]!;
    for (const [k, v] of Object.entries(params)) {
      if (!allowed.has(k)) errors.push(`actions[${i}].params.${k}: not a typed parameter for ${String(action.type)}`);
      if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") {
        errors.push(`actions[${i}].params.${k}: parameters must be scalar values`);
      }
    }
    if (action.type === "SET_PRIORITY" && params.priority !== undefined && !SETTABLE_PRIORITIES.has(String(params.priority))) {
      errors.push(`actions[${i}].params.priority must be one of P0–P4 (policy-bounded, §60)`);
    }
  });
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, errors: [], value: doc as unknown as SecurityWorkflowDsl };
}

export interface WorkflowEventView {
  trigger: string;
  severity?: string;
  priority?: string;
  environment?: string;
  assetType?: string;
  verification?: string;
  kev?: boolean;
  riskScore?: number;
  owner?: string;
  tags?: string[];
  domain?: string;
  findingId?: string;
  assetId?: string;
}

function fieldValue(event: WorkflowEventView, field: ConditionField): unknown {
  switch (field) {
    case "severity": return event.severity;
    case "priority": return event.priority;
    case "environment": return event.environment;
    case "assetType": return event.assetType;
    case "verification": return event.verification;
    case "kev": return event.kev;
    case "riskScore": return event.riskScore;
    case "owner": return event.owner;
    case "tag": return event.tags;
    case "domain": return event.domain;
  }
}

export function matchesCondition(event: WorkflowEventView, condition: WorkflowCondition): boolean {
  const actual = fieldValue(event, condition.field);
  const expected = condition.value;
  switch (condition.operator) {
    case "eq": return actual === expected;
    case "neq": return actual !== expected;
    case "in": return Array.isArray(expected) && (expected as unknown[]).includes(actual);
    case "gte": return typeof actual === "number" && typeof expected === "number" && actual >= expected;
    case "lte": return typeof actual === "number" && typeof expected === "number" && actual <= expected;
    case "contains":
      if (Array.isArray(actual)) return actual.includes(expected);
      return typeof actual === "string" && typeof expected === "string" && actual.includes(expected);
  }
}

export function matchesWorkflow(event: WorkflowEventView, dsl: SecurityWorkflowDsl): boolean {
  if (event.trigger !== dsl.trigger) return false;
  return dsl.conditions.every((c) => matchesCondition(event, c));
}

/** §63: hard cap on workflow-triggered workflow chains. */
export const MAX_WORKFLOW_DEPTH = 3;

export function workflowDedupKey(workflowId: string, eventId: string, actionType: string): string {
  return createHash("sha256").update(`workflow:${workflowId}:${eventId}:${actionType}`).digest("hex");
}

export interface LoopGuardInput {
  /** Workflow ids already in this event's causal lineage. */
  lineage: string[];
  depth: number;
  workflowId: string;
  /** Dedup keys already executed for this event lineage. */
  executedKeys: Set<string>;
  eventId: string;
  actionType: string;
}

export function checkLoopGuard(input: LoopGuardInput): { allowed: boolean; reason?: string; dedupKey: string } {
  const dedupKey = workflowDedupKey(input.workflowId, input.eventId, input.actionType);
  if (input.depth >= MAX_WORKFLOW_DEPTH) {
    return { allowed: false, dedupKey, reason: `workflow execution depth ${input.depth} reached the cap ${MAX_WORKFLOW_DEPTH} (§63)` };
  }
  if (input.lineage.includes(input.workflowId)) {
    return { allowed: false, dedupKey, reason: `workflow ${input.workflowId} is already in this event's lineage — recursive self-trigger blocked (§63)` };
  }
  if (input.executedKeys.has(dedupKey)) {
    return { allowed: false, dedupKey, reason: "identical workflow action already executed for this event (dedup key, §63)" };
  }
  return { allowed: true, dedupKey };
}
