/**
 * Prompt 18 — controlled debugging policy (§64–§74).
 *
 * Debugging is NEVER the default workflow. A debug session may be
 * ELIGIBLE only when ALL of these hold: LAB environment, authorized
 * artifact, verified target, explicit approval by a separate
 * approver, a BINARY_DYNAMIC_LAB worker, a network policy (default
 * NO_NETWORK), a hard timeout, a session budget and NO active kill
 * switch. Operations are typed (§69) — there is no operation that
 * carries an arbitrary GDB command, Python snippet or shell text
 * (§68/§93/§114), and the prohibited list (§68/§123) is refused by
 * name. In this build no debugger transport is provisioned, so even
 * an ELIGIBLE session honestly reports NOT_PROVISIONED at start —
 * the policy + session architecture is complete; live debugging is
 * a deployment provisioning step, never a fabrication.
 */
import { isProhibitedBinaryAction } from "./types";

/** §69: the ONLY debug operations that exist. */
export const DEBUG_OPERATIONS = [
  "START_APPROVED_FIXTURE",
  "SET_APPROVED_BREAKPOINT",
  "INSPECT_REGISTER_METADATA",
  "INSPECT_BOUNDED_MEMORY",
  "CAPTURE_CRASH_METADATA",
  "TERMINATE_SESSION",
] as const;
export type DebugOperation = (typeof DEBUG_OPERATIONS)[number];

/** §68: prohibited debug behavior — refused by name, always. */
export const PROHIBITED_DEBUG_ACTIONS = [
  "UNRESTRICTED_DEBUGGER_SHELL",
  "ARBITRARY_GDB_COMMAND",
  "ARBITRARY_DEBUGGER_PYTHON",
  "DEBUG_UNAUTHORIZED_SYSTEM",
  "ATTACH_PRODUCTION_PROCESS",
  "CREDENTIAL_EXTRACTION",
  "PROCESS_INJECTION",
  "PRIVILEGE_ESCALATION",
  "AV_EDR_BYPASS",
  "MEMORY_EXFILTRATION_AT_SCALE",
  "KERNEL_DEBUG_UNAUTHORIZED",
  "PERSISTENCE_INSTALLATION",
] as const;

export interface DebugOperationRequest {
  operation: string;
  /** Bounded parameters for typed operations — never command text. */
  params?: Record<string, number | string | boolean>;
}

export function validateDebugOperations(ops: DebugOperationRequest[]): { ok: boolean; refused?: string } {
  for (const op of ops) {
    const name = op.operation.toUpperCase();
    if (isProhibitedBinaryAction(name) || (PROHIBITED_DEBUG_ACTIONS as readonly string[]).includes(name)) {
      return { ok: false, refused: `Debug action ${name} is PROHIBITED (§68/§123)` };
    }
    if (!(DEBUG_OPERATIONS as readonly string[]).includes(name)) {
      return { ok: false, refused: `Debug operation "${op.operation}" is not a typed approved operation (§69)` };
    }
    for (const [k, v] of Object.entries(op.params ?? {})) {
      if (/command|script|shell|python|code/i.test(k)) {
        return { ok: false, refused: `Debug operation parameter "${k}" would carry command/script text (§68/§93)` };
      }
      if (typeof v === "string" && /[;|&`$]|\.\.\//.test(v)) {
        return { ok: false, refused: `Debug operation parameter "${k}" carries shell-shaped content (§68)` };
      }
    }
  }
  return { ok: true };
}

export interface BinaryDebugPolicyInput {
  environment: string; // artifact/target environment
  artifactAuthorized: boolean;
  targetVerified: boolean;
  requestedBy: string;
  approvedBy?: string;
  approvalExpiresAt?: string; // ISO
  workerCapabilityPresent: boolean;
  networkPolicy?: string; // default NO_NETWORK
  timeoutSeconds?: number;
  budgetSeconds?: number;
  killSwitchActive: boolean;
  operations: DebugOperationRequest[];
  now?: Date;
}

export interface BinaryDebugPolicyDecision {
  decision: "ELIGIBLE" | "PENDING_APPROVAL" | "BLOCKED";
  reasons: string[];
  networkPolicy: string;
  timeoutSeconds: number;
}

export function evaluateBinaryDebugPolicy(input: BinaryDebugPolicyInput): BinaryDebugPolicyDecision {
  const reasons: string[] = [];
  const opsCheck = validateDebugOperations(input.operations);
  if (!opsCheck.ok) reasons.push(opsCheck.refused!);
  if (input.environment !== "LAB") reasons.push(`Debugging is permitted only in a LAB environment (§64) — environment is ${input.environment}: BLOCKED`);
  if (!input.artifactAuthorized) reasons.push("Artifact is not authorized for this assessment (§64)");
  if (!input.targetVerified) reasons.push("Target is not VERIFIED (§64)");
  if (input.killSwitchActive) reasons.push("A kill switch is ACTIVE for this scope — session blocked (§71)");
  if (!input.workerCapabilityPresent) reasons.push("No BINARY_DYNAMIC_LAB worker is available for the session (§64/§72)");
  const timeout = Math.min(input.timeoutSeconds ?? 1800, 1800);
  if (timeout <= 0) reasons.push("Debug session timeout must be positive and is hard-capped (§67)");

  let approvalState: "OK" | "PENDING" | "INVALID" = "PENDING";
  if (input.approvedBy) {
    if (input.approvedBy === input.requestedBy) {
      approvalState = "INVALID";
      reasons.push("Separation of duties: the requester cannot approve their own debug session (§67)");
    } else if (input.approvalExpiresAt && new Date(input.approvalExpiresAt) <= (input.now ?? new Date())) {
      approvalState = "INVALID";
      reasons.push("Debug approval has expired (§67)");
    } else {
      approvalState = "OK";
    }
  }

  const hardBlocked = reasons.length > 0;
  if (hardBlocked) return { decision: "BLOCKED", reasons, networkPolicy: input.networkPolicy ?? "NO_NETWORK", timeoutSeconds: timeout };
  if (approvalState !== "OK") {
    return { decision: "PENDING_APPROVAL", reasons: ["Awaiting approval by a separate approver with APPROVE_BINARY_DEBUG (§67/§94)"], networkPolicy: input.networkPolicy ?? "NO_NETWORK", timeoutSeconds: timeout };
  }
  return { decision: "ELIGIBLE", reasons: [], networkPolicy: input.networkPolicy ?? "NO_NETWORK", timeoutSeconds: timeout };
}

/** §81: dynamic conclusions remain separate from static ones — a
 *  dynamic observation may CONFIRM, REJECT_AS_FALSE_POSITIVE (with
 *  evidence), leave INCONCLUSIVE or raise a NEW finding. */
export const DYNAMIC_VALIDATION_OUTCOMES = [
  "CONFIRMED", "REJECTED_AS_FALSE_POSITIVE", "INCONCLUSIVE", "NEW_FINDING_RAISED",
] as const;
