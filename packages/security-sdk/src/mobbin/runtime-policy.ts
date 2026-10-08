/**
 * Prompt 35 §75–§84 — ADB / Frida / Objection defensive policy.
 *
 * These evaluators are pure policy: they decide whether a requested
 * operation is inside the approved defensive envelope. They never
 * execute a command. The shape of the envelope is closed — anything
 * not explicitly allowlisted is rejected, and the historically
 * dangerous requests (arbitrary adb shell §77/§150, unreviewed
 * Frida scripts §79/§152, arbitrary Objection commands §84) are
 * rejected by construction, not by blocklist.
 */

// ── ADB (§75–§77) ──────────────────────────────────────────────────

/** §75: the complete allowlist of ADB operations the platform can
 *  ever request against an authorized lab device. */
export const ADB_ALLOWED_OPERATIONS = [
  "DEVICE_STATUS",
  "INSTALL_AUTHORIZED_APP",
  "LAUNCH_TEST_APP",
  "STOP_TEST_APP",
  "COLLECT_LOGS",
  "TRANSFER_TEST_ARTIFACT",
] as const;
export type AdbOperation = (typeof ADB_ALLOWED_OPERATIONS)[number];

export interface AdbPolicyVerdict {
  allowed: boolean;
  operation: string;
  reasons: string[];
}

/** §77/§150: no arbitrary user-supplied adb shell — a request naming
 *  anything outside the allowlist (including "shell" itself, in any
 *  spelling) is REJECTED. §76 prohibitions (unrelated app data,
 *  credential theft, persistence) can never be allowlisted because
 *  they are not operations in the closed set. */
export function evaluateAdbOperation(operation: string): AdbPolicyVerdict {
  const normalized = operation.trim().toUpperCase().replace(/[\s-]+/g, "_");
  const reasons: string[] = [];
  if (normalized.includes("SHELL")) reasons.push("ARBITRARY_ADB_SHELL: no generic adb shell exists in DSRclone (§59/§75/§77)");
  if (!(ADB_ALLOWED_OPERATIONS as readonly string[]).includes(normalized)) {
    reasons.push(`OPERATION_NOT_ALLOWLISTED: '${operation}' is not one of the approved ADB operations (§75)`);
  }
  return { allowed: reasons.length === 0, operation: normalized, reasons };
}

// ── Frida script registry (§80–§82) ────────────────────────────────

export const FRIDA_RISK_CLASSES = ["LOW", "MEDIUM", "HIGH"] as const;

/** §81: canonical approved instrumentation module purposes. */
export const APPROVED_INSTRUMENTATION_PURPOSES = [
  "RUNTIME_METHOD_OBSERVATION",
  "CRYPTO_API_OBSERVATION",
  "SECURE_STORAGE_VERIFICATION",
  "NETWORK_STACK_OBSERVATION",
  "PINNING_VERIFICATION",
] as const;

export interface FridaScriptRegistryEntry {
  id: string;
  version: string;
  purpose: string;
  platform: string;
  riskClass: string;
  /** SHA-256 of the reviewed script artifact. */
  hash: string;
  reviewStatus: string; // REGISTERED | APPROVED | DISABLED
}

export interface FridaPolicyVerdict {
  allowed: boolean;
  reasons: string[];
}

/** §79/§80/§152: a Frida script may run only as a registry entry
 *  with complete identity (id, version, purpose, platform, risk
 *  class, hash) AND review status APPROVED. Inline/arbitrary script
 *  bodies are not a request shape at all — a caller supplying one is
 *  rejected outright. Pinning verification (§82) is observation of a
 *  test app's control behaviour, never a generic bypass service. */
export function evaluateFridaScriptRequest(input: {
  registryEntry?: FridaScriptRegistryEntry | null;
  scriptBody?: string | null;
}): FridaPolicyVerdict {
  const reasons: string[] = [];
  if (input.scriptBody) reasons.push("ARBITRARY_SCRIPT: unrestricted Frida script execution is not exposed (§79/§152)");
  const e = input.registryEntry;
  if (!e) {
    reasons.push("NO_REGISTRY_ENTRY: runtime instrumentation requires a registered, reviewed script (§80)");
    return { allowed: false, reasons };
  }
  if (!e.id || !e.version || !e.purpose || !e.platform || !e.riskClass || !e.hash) {
    reasons.push("INCOMPLETE_REGISTRY_ENTRY: id, version, purpose, platform, risk class and hash are all required (§80)");
  }
  if (!(FRIDA_RISK_CLASSES as readonly string[]).includes(e.riskClass)) reasons.push(`UNKNOWN_RISK_CLASS: '${e.riskClass}'`);
  if (e.reviewStatus !== "APPROVED") reasons.push("SCRIPT_NOT_APPROVED: only reviewed + approved registry scripts may run (§80/§152)");
  if (!/^[a-f0-9]{64}$/i.test(e.hash ?? "")) reasons.push("INVALID_SCRIPT_HASH: registry hash must be a SHA-256 hex digest (§80)");
  return { allowed: reasons.length === 0, reasons };
}

// ── Objection (§83/§84) ────────────────────────────────────────────

/** §83: the closed set of approved defensive Objection workflows. */
export const OBJECTION_APPROVED_WORKFLOWS = [
  "APP_STORAGE_INVENTORY",
  "KEYCHAIN_CLASS_OBSERVATION",
  "ROOT_DETECTION_BEHAVIOUR_CHECK",
  "SSL_PINNING_BEHAVIOUR_CHECK",
  "ENVIRONMENT_INVENTORY",
] as const;

export function evaluateObjectionWorkflow(workflow: string): { allowed: boolean; reasons: string[] } {
  const normalized = workflow.trim().toUpperCase().replace(/[\s-]+/g, "_");
  const reasons: string[] = [];
  if (!(OBJECTION_APPROVED_WORKFLOWS as readonly string[]).includes(normalized)) {
    reasons.push(`WORKFLOW_NOT_APPROVED: '${workflow}' is not an approved defensive workflow — arbitrary interactive device commands are never exposed (§83/§84)`);
  }
  return { allowed: reasons.length === 0, reasons };
}
