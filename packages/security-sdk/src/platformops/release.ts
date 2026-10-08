import type { PlatformControlState, ReleaseMetadata } from "./types";

/**
 * Release & operator controls (Prompt 38 §147–§159): immutable release
 * metadata, feature flags for risky staged rollouts, operator kill
 * switches and maintenance mode. Evaluation is pure and total — an
 * unknown flag is OFF, an unknown switch is OFF, and a missing control
 * record means normal operation (controls are additive safety, and a
 * broken control read must fail OPEN for reads but is surfaced in the
 * admin view; work-class gates fail CLOSED via assertWorkAllowed when
 * the caller requires it).
 */

export const FEATURE_FLAGS = [
  "BETA_SCANNER_PROFILES",
  "AI_V2_WORKFLOWS",
  "CLIENT_PORTAL_V2",
] as const;
export type FeatureFlag = (typeof FEATURE_FLAGS)[number];

export function featureFlagEnabled(
  flag: string,
  flags: Record<string, boolean> | undefined,
): boolean {
  if (!(FEATURE_FLAGS as readonly string[]).includes(flag)) return false;
  return flags?.[flag] === true;
}

export function validateReleaseMetadata(meta: Partial<ReleaseMetadata>): string[] {
  const problems: string[] = [];
  if (!meta.version) problems.push("release version is required (§156)");
  if (!meta.commit) problems.push("release commit is required (§156)");
  else if (!/^[0-9a-f]{7,64}$/i.test(meta.commit)) problems.push("release commit must be a git SHA");
  if (!meta.environment) problems.push("release environment is required");
  return problems;
}

/** Which work classes a control state blocks. Reads/health/admin are
 *  never blocked — operators must always be able to see and fix. */
export type WorkClass = "SCAN_START" | "AI_REQUEST" | "INTEGRATION_SYNC" | "REPORT_JOB" | "READ" | "ADMIN";

const SWITCH_FOR_WORK: Partial<Record<WorkClass, string>> = {
  SCAN_START: "SCAN_STARTS",
  AI_REQUEST: "AI_WORKFLOWS",
  INTEGRATION_SYNC: "INTEGRATION_SYNC",
  REPORT_JOB: "REPORT_JOBS",
};

export interface WorkDecision { allowed: boolean; reason?: string }

export function evaluateWork(control: PlatformControlState | null, work: WorkClass): WorkDecision {
  if (work === "READ" || work === "ADMIN") return { allowed: true };
  if (!control) return { allowed: true };
  const switchName = SWITCH_FOR_WORK[work];
  if (switchName && control.killSwitches[switchName as keyof typeof control.killSwitches]?.enabled) {
    const st = control.killSwitches[switchName as keyof typeof control.killSwitches]!;
    return { allowed: false, reason: `kill switch ${switchName} is enabled${st.reason ? `: ${st.reason}` : ""}` };
  }
  if (control.maintenanceMode) {
    return { allowed: false, reason: `platform is in maintenance mode${control.maintenanceMessage ? `: ${control.maintenanceMessage}` : ""}` };
  }
  return { allowed: true };
}
