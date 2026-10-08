import { MOBBIN_DEFAULT_LIMITS, mobbinProfileDefinition } from "./profiles";
import type { MobileAnalysisPlanV2, MobbinPlatform } from "./types";

/**
 * Prompt 35 §13/§14/§16 — the mobile analysis plan builder and its
 * dynamic gate.
 *
 * The orchestrator pipeline (§14) is INGEST → CLASSIFY →
 * STATIC_ANALYSIS → DEPENDENCY_ANALYSIS → SECRET_ANALYSIS →
 * BINARY_HARDENING → OPTIONAL_DYNAMIC_ANALYSIS → TRAFFIC_ANALYSIS →
 * NORMALIZATION → CORRELATION → RISK → REMEDIATION → REPORT. The
 * dynamic stage is OPTIONAL and gated: it is ALLOWED only when the
 * app + build carry an authorization, the device is an explicitly
 * AUTHORIZED lab device (§72–§74), and at least one reviewed
 * instrumentation module is approved (§80). Anything less records
 * the plan with dynamic BLOCKED and the reasons — never a silent
 * downgrade, never an implicit authorization.
 */
export interface BuildMobilePlanInput {
  profile: string;
  platform: MobbinPlatform;
  artifactHash: string;
  /** Authorization record id attached to the app/build, if any. */
  authorizationId?: string | null;
  device?: { id: string; deviceType: string; authorizationStatus: string; availability: string } | null;
  /** Count of reviewed+approved instrumentation modules available. */
  approvedModuleCount?: number;
  trafficAnalysis?: boolean;
  verificationPolicy?: "TARGETED_RETEST" | "MANUAL_REVIEW";
}

export function buildMobileAnalysisPlan(input: BuildMobilePlanInput): MobileAnalysisPlanV2 {
  const def = mobbinProfileDefinition(input.profile);
  if (!def) throw new Error(`Unknown mobile/binary V2 profile: ${input.profile}`);
  if (def.platform !== "ANY" && def.platform !== "BINARY" && def.platform !== input.platform) {
    throw new Error(`Profile ${input.profile} does not apply to platform ${input.platform}`);
  }
  const wantsDynamic = def.dynamicModules.length > 0;
  const reasons: string[] = [];
  let dynamicGate: MobileAnalysisPlanV2["dynamicGate"] = "NOT_REQUESTED";
  if (wantsDynamic) {
    if (!input.authorizationId) reasons.push("NO_AUTHORIZATION: dynamic analysis requires an explicit authorization for this application (§71)");
    if (!input.device) reasons.push("NO_DEVICE: dynamic analysis requires a registered lab device profile (§72)");
    else {
      if (input.device.authorizationStatus !== "AUTHORIZED") reasons.push("DEVICE_NOT_AUTHORIZED: the device is not an authorized test device (§74/§151)");
      if (input.device.availability !== "AVAILABLE") reasons.push("DEVICE_UNAVAILABLE: the device is not AVAILABLE");
    }
    if ((input.approvedModuleCount ?? 0) < 1) reasons.push("NO_APPROVED_MODULE: runtime observation requires at least one reviewed, approved instrumentation module (§80/§81)");
    dynamicGate = reasons.length === 0 ? "ALLOWED" : "BLOCKED";
  }
  return {
    profile: def.profile,
    platform: input.platform,
    artifactHash: input.artifactHash,
    authorizationId: input.authorizationId ?? null,
    staticModules: [...def.staticModules],
    dynamicModules: wantsDynamic ? [...def.dynamicModules] : [],
    dynamicGate,
    dynamicGateReasons: reasons,
    deviceProfile: input.device ? { deviceId: input.device.id, deviceType: input.device.deviceType } : null,
    trafficAnalysis: input.trafficAnalysis === true && wantsDynamic,
    limits: { ...MOBBIN_DEFAULT_LIMITS },
    verificationPolicy: input.verificationPolicy ?? "TARGETED_RETEST",
  };
}
