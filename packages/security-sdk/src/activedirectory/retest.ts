/**
 * Prompt 15 — Active Directory retest planning (§84).
 *
 * A retest re-queries ONLY the affected object with a read-only
 * collection or the dedicated posture section, then re-evaluates the
 * original rule against the fresh evidence. Retests never widen scope
 * and never run an offensive capability: findings from the SMB stage
 * retest through the SMB inventory adapters; AD CS findings retest
 * through the Certipy POSTURE adapter; graph findings retest through
 * the platform ATTACK_PATH stage over a fresh collection.
 */
export interface AdRetestPlan {
  stageType: string;
  adapterSlug?: string;
  /** Platform analysis section when the retest is pure analysis over
   *  freshly collected inventory (no tool stage re-run). */
  section?: "LDAP_POSTURE" | "GRAPH" | "ATTACK_PATH";
  readOnly: true;
  reason: string;
}

const SMB_RULES = new Set(["AD_SMB1_ENABLED", "AD_SMB_SIGNING_NOT_REQUIRED", "AD_SMB_ANONYMOUS_SHARE", "AD_SMB_WRITABLE_SHARE"]);
const LDAP_RULES = new Set(["AD_LDAP_SIGNING_NOT_REQUIRED", "AD_LDAP_CHANNEL_BINDING_WEAK", "AD_DC_SERVICE_EXPOSURE"]);

export function planAdRetest(input: { ruleId?: string; sourceTool?: string }): AdRetestPlan {
  const ruleId = input.ruleId ?? "";
  if (ruleId.startsWith("ADCS_") || input.sourceTool === "certipy-posture") {
    return {
      stageType: "ADCS_POSTURE", adapterSlug: "certipy-posture", readOnly: true,
      reason: "AD CS findings retest through the Certipy posture adapter (FIND only) over the affected CA/template (§84)",
    };
  }
  if (SMB_RULES.has(ruleId)) {
    return {
      stageType: "SMB_POSTURE", adapterSlug: "smbmap", readOnly: true,
      reason: "SMB findings retest through the governed share-inventory adapters — contents are never fetched (§84/§44)",
    };
  }
  if (LDAP_RULES.has(ruleId)) {
    return {
      stageType: "LDAP_POSTURE", section: "LDAP_POSTURE", readOnly: true,
      reason: "LDAP/DC posture retests re-evaluate the dedicated LDAP posture section over a fresh read-only collection (§84)",
    };
  }
  if (input.sourceTool === "pingcastle") {
    return {
      stageType: "PINGCASTLE_POSTURE", adapterSlug: "pingcastle", readOnly: true,
      reason: "PingCastle findings retest through a fresh healthcheck import (§84)",
    };
  }
  // Identity, delegation, ACL, trust and account-posture findings
  // retest through a fresh directory collection + platform analysis —
  // the original stage for most is DIRECTORY_INVENTORY.
  return {
    stageType: "DIRECTORY_INVENTORY", adapterSlug: "ldap-directory-connector", readOnly: true,
    reason: "identity findings retest through a fresh read-only directory collection and platform posture analysis (§84)",
  };
}
