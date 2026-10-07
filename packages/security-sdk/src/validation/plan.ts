import { createHash } from "node:crypto";
import { FORBIDDEN_INPUT_FIELDS } from "../adapter/adapter.types";
import { getValidator } from "./catalog";
import {
  VALIDATION_PLAN_STAGES,
  type ValidationBudget,
  type ValidationFindingView,
  type ValidationPlan,
} from "./types";

/**
 * Validation plan construction (Prompt 16 §13) and the API-safety gate
 * (§79/§90). A plan is a FIXED DAG over a governed validator with
 * allowlisted typed parameters. There is no field anywhere in a plan
 * that can carry a shell command, a scanner CLI argument, an arbitrary
 * payload or a script: unknown/forbidden keys are rejected at plan
 * time, and string parameter values containing shell metacharacters are
 * rejected as data-poisoning attempts (§90) — defense in depth on top of
 * the fact that validators never invoke a shell.
 */

export const FORBIDDEN_PLAN_FIELDS: readonly string[] = [
  ...FORBIDDEN_INPUT_FIELDS,
  "payload",
  "template",
  "templateContent",
  "url_override",
  "rawRequest",
  "binary",
  "image",
];

/** Shell metacharacters that must never appear in a configuration value
 *  (§90): ; & | $() backticks, newlines, redirects. Values are data. */
const SHELL_METACHAR_RE = /[;&|`$<>\n\r]|\$\(/;

export function containsShellMetachars(value: string): boolean {
  return SHELL_METACHAR_RE.test(value);
}

export class ValidationPlanError extends Error {
  constructor(
    message: string,
    readonly code: "FORBIDDEN_FIELD" | "UNKNOWN_VALIDATOR" | "INVALID_PARAMETER" | "SHELL_METACHARS" | "UNSUPPORTED_FINDING",
  ) {
    super(message);
    this.name = "ValidationPlanError";
  }
}

function assertNoForbiddenKeys(value: unknown, path: string): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoForbiddenKeys(v, `${path}[${i}]`));
    return;
  }
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_PLAN_FIELDS.includes(key)) {
      throw new ValidationPlanError(
        `field "${path}.${key}" is forbidden — validation plans never carry commands, payloads, scripts or raw templates (§79)`,
        "FORBIDDEN_FIELD",
      );
    }
    assertNoForbiddenKeys(v, `${path}.${key}`);
  }
}

/** Validate caller-supplied parameters against the validator's closed
 *  parameter spec: only declared names, only declared types, bounded
 *  length, closed enums, and no shell metacharacters (§79/§90). */
export function validateValidatorParameters(
  validatorSlug: string,
  parameters: Record<string, unknown> | undefined,
): Record<string, string | number | boolean> {
  const validator = getValidator(validatorSlug);
  if (!validator) throw new ValidationPlanError(`unknown validator "${validatorSlug}"`, "UNKNOWN_VALIDATOR");
  const out: Record<string, string | number | boolean> = {};
  if (parameters === undefined) return out;
  assertNoForbiddenKeys(parameters, "parameters");
  for (const [key, value] of Object.entries(parameters)) {
    const spec = validator.parameters.find((p) => p.name === key);
    if (!spec) {
      throw new ValidationPlanError(
        `parameter "${key}" is not declared for validator ${validatorSlug} — parameters are allowlisted (§79)`,
        "INVALID_PARAMETER",
      );
    }
    if (typeof value !== spec.type) {
      throw new ValidationPlanError(`parameter "${key}" must be of type ${spec.type}`, "INVALID_PARAMETER");
    }
    if (spec.type === "string") {
      const s = value as string;
      if (spec.maxLength !== undefined && s.length > spec.maxLength) {
        throw new ValidationPlanError(`parameter "${key}" exceeds ${spec.maxLength} characters`, "INVALID_PARAMETER");
      }
      if (containsShellMetachars(s)) {
        throw new ValidationPlanError(
          `parameter "${key}" contains shell metacharacters — values are treated as data and metacharacters are rejected (§90)`,
          "SHELL_METACHARS",
        );
      }
      if (spec.enum && !spec.enum.includes(s)) {
        throw new ValidationPlanError(`parameter "${key}" must be one of: ${spec.enum.join(", ")}`, "INVALID_PARAMETER");
      }
    }
    out[key] = value as string | number | boolean;
  }
  return out;
}

/** Deterministic JSON (stable key order) — the basis of the plan hash. */
export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalStringify(v)}`).join(",")}}`;
}

/** §10: the approval binds to this hash. ANY plan change — validator,
 *  target, parameter, budget — produces a different hash and voids
 *  prior approvals. */
export function hashValidationPlan(plan: ValidationPlan): string {
  return createHash("sha256").update(canonicalStringify(plan)).digest("hex");
}

export interface BuildPlanInput {
  validatorSlug: string;
  finding: ValidationFindingView;
  targetId: string;
  parameters?: Record<string, unknown>;
  budget: ValidationBudget;
}

export function buildValidationPlan(input: BuildPlanInput): { plan: ValidationPlan; planHash: string } {
  const validator = getValidator(input.validatorSlug);
  if (!validator) throw new ValidationPlanError(`unknown validator "${input.validatorSlug}"`, "UNKNOWN_VALIDATOR");
  if (!validator.supportsFinding(input.finding)) {
    throw new ValidationPlanError(
      `validator ${validator.slug} does not support this finding — no safe validation exists for it in the catalog (§6)`,
      "UNSUPPORTED_FINDING",
    );
  }
  const parameters = validateValidatorParameters(input.validatorSlug, input.parameters);
  const f = input.finding;
  const plan: ValidationPlan = {
    version: 1,
    validatorSlug: validator.slug,
    validationType: validator.validationType,
    riskClass: validator.riskClass,
    ...(validator.toolSlug ? { toolSlug: validator.toolSlug } : {}),
    findingId: f.id,
    targetId: input.targetId,
    targetRef: {
      ...(f.host ? { host: f.host } : {}),
      ...(f.port ? { port: f.port } : {}),
      ...(f.endpoint ? { endpoint: f.endpoint } : {}),
      ...(f.cloudResourceId ? { cloudResourceId: f.cloudResourceId } : {}),
      ...(f.clusterRef ? { clusterRef: f.clusterRef } : {}),
      ...(f.repositoryId ? { repositoryId: f.repositoryId } : {}),
      ...(f.imageDigest ? { imageDigest: f.imageDigest } : {}),
      ...(f.directoryObjectId ? { directoryObjectId: f.directoryObjectId } : {}),
    },
    parameters,
    budget: input.budget,
    stages: [...VALIDATION_PLAN_STAGES],
  };
  assertNoForbiddenKeys(plan, "plan");
  return { plan, planHash: hashValidationPlan(plan) };
}
