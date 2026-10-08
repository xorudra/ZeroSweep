/** Authentication risk signals (§46–47). Policy-driven responses; no weak
 *  geolocation guess is ever a sole blocking signal. */
export interface AuthRiskSignals {
  newDevice: boolean;
  excessiveFailures: boolean;
  impossibleSessionState: boolean;
  suspiciousSessionReuse: boolean;
  authenticationDowngrade: boolean;
  failureCountLastHour: number;
}
export type RiskResponse = "ALLOW" | "REQUIRE_MFA" | "REQUIRE_STEP_UP" | "BLOCK";

export function evaluateAuthRisk(signals: AuthRiskSignals): { response: RiskResponse; reasons: string[] } {
  const reasons: string[] = [];
  if (signals.impossibleSessionState) reasons.push("Session presented from two mutually exclusive contexts");
  if (signals.suspiciousSessionReuse) reasons.push("Revoked or rotated session token was replayed");
  if (reasons.length > 0) return { response: "BLOCK", reasons };
  if (signals.authenticationDowngrade) { reasons.push("Authentication assurance downgraded mid-session"); return { response: "REQUIRE_STEP_UP", reasons }; }
  if (signals.excessiveFailures || signals.failureCountLastHour >= 10) { reasons.push("Excessive recent authentication failures"); return { response: "REQUIRE_STEP_UP", reasons }; }
  if (signals.newDevice) { reasons.push("First authentication from this device"); return { response: "REQUIRE_MFA", reasons }; }
  return { response: "ALLOW", reasons };
}
