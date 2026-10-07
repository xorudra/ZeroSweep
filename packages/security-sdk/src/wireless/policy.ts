/**
 * Prompt 19 — wireless policy (§20/§64/§65/§93/§99).
 *
 * Three policies, one posture: PASSIVE ONLY in baseline.
 *  - AircrackPolicy (§20): the aircrack-ng family may inspect
 *    captures and extract metadata. Cracking, key recovery and
 *    deauthentication workflows are DISABLED — refused at config
 *    validation, at plan time and at the API, and audited.
 *  - ActiveToolPolicy (§64): Wifite and active hcxdumptool modes are
 *    outside baseline orchestration — ToolSelector-facing data so a
 *    baseline profile can never select them.
 *  - WirelessLabPolicy (§65): the lab-validation ARCHITECTURE —
 *    explicit LAB environment, dedicated test AP/clients,
 *    authorization, approval, hard timeout, kill switch. No lab
 *    transport or active tooling is provisioned in this build, so an
 *    eligible request evaluates to NOT_PROVISIONED rather than
 *    fabricating a lab run (§65/§72-analog discipline).
 */
import { isProhibitedWirelessAction, PROHIBITED_WIRELESS_AUTOMATION } from "./types";

// ── Aircrack (§19/§20) ──────────────────────────────────────────────

export const AIRCRACK_ALLOWED_CAPABILITIES = [
  "CAPTURE_METADATA_ANALYSIS", "WIRELESS_CONFIGURATION_ANALYSIS", "OFFLINE_CAPTURE_INSPECTION",
] as const;

export const AIRCRACK_DISABLED_WORKFLOWS = [
  "CREDENTIAL_CRACKING", "KEY_RECOVERY", "DEAUTHENTICATION", "DICTIONARY_ATTACK", "WORDLIST_ATTACK",
] as const;

/** Config keys that would turn the metadata adapter into a cracking
 *  or transmitting tool. Their presence refuses the configuration. */
const AIRCRACK_FORBIDDEN_CONFIG_KEYS = /^(wordlist|dictionary|key|keys|deauth|deauthenticate|ivs|korek|chopchop|fragmentation|interactive|replay|arp)/i;
const GENERIC_FORBIDDEN_KEYS = /crack|wordlist|dictionary|deauth|jam|spoof|rogue|eviltwin|password/i;

export interface WirelessPolicyDecision {
  allowed: boolean;
  reasonCode?: string;
  reason?: string;
}

export function evaluateAircrackConfig(config: Record<string, unknown>): WirelessPolicyDecision {
  for (const key of Object.keys(config)) {
    if (AIRCRACK_FORBIDDEN_CONFIG_KEYS.test(key) || GENERIC_FORBIDDEN_KEYS.test(key)) {
      return {
        allowed: false, reasonCode: "AIRCRACK_WORKFLOW_DISABLED",
        reason: `aircrack-ng config key "${key}" names a disabled workflow (§20): cracking, key recovery and deauthentication are prohibited automation in this platform (§99)`,
      };
    }
  }
  return { allowed: true };
}

/** §78/§93: ANY wireless adapter config carrying command/filter/
 *  shell-shaped keys is refused — plans are composed from typed
 *  platform constants only. */
export function assertWirelessConfigKeys(config: Record<string, unknown>): WirelessPolicyDecision {
  for (const key of Object.keys(config)) {
    if (/^(command|commands|shell|shellcommand|args|argv|filter|displayfilter|exec|script)$/i.test(key)) {
      return {
        allowed: false, reasonCode: "WIRELESS_COMMAND_NOT_EXPRESSIBLE",
        reason: `wireless config key "${key}" is forbidden: raw commands, arguments and display filters are not expressible (§78)`,
      };
    }
    if (/credential|secret|token|password|privatekey|psk/i.test(key)) {
      return {
        allowed: false, reasonCode: "WIRELESS_CREDENTIAL_NOT_EXPRESSIBLE",
        reason: `wireless config key "${key}" is forbidden: credentials exist only as secret references, and Wi-Fi credentials are never stored or cracked (§66/§67)`,
      };
    }
  }
  return { allowed: true };
}

export function evaluateWirelessAction(action: string): WirelessPolicyDecision {
  if (isProhibitedWirelessAction(action)) {
    return {
      allowed: false, reasonCode: "WIRELESS_PROHIBITED_AUTOMATION",
      reason: `"${action}" is prohibited automation (§99): ${PROHIBITED_WIRELESS_AUTOMATION.join(", ")} are never implemented or executed`,
    };
  }
  return { allowed: true };
}

// ── Active tool safety (§64) ────────────────────────────────────────

/** Slugs ToolSelector must NEVER select for baseline profiles. They
 *  have no adapters at all — this list is the second, explicit lock
 *  (§64/§93: a baseline run that names one is BLOCKED + audited). */
export const WIRELESS_BASELINE_FORBIDDEN_SLUGS = ["wifite", "hcxdumptool"] as const;

export const WIRELESS_BASELINE_PROFILES = [
  "WIRELESS_PASSIVE_BASELINE", "WIRELESS_PASSIVE_COMPREHENSIVE", "PCAP_ANALYSIS_ONLY", "WIRELESS_COMPLIANCE",
] as const;

export function evaluateActiveToolRequest(input: { slug: string; profile: string }): WirelessPolicyDecision {
  if ((WIRELESS_BASELINE_FORBIDDEN_SLUGS as readonly string[]).includes(input.slug)
    && (WIRELESS_BASELINE_PROFILES as readonly string[]).includes(input.profile)) {
    return {
      allowed: false, reasonCode: "WIRELESS_ACTIVE_TOOL_BLOCKED",
      reason: `${input.slug} is an active wireless tool and is BLOCKED for profile ${input.profile} (§64): Wifite and active hcxdumptool modes remain outside baseline orchestration`,
    };
  }
  if ((WIRELESS_BASELINE_FORBIDDEN_SLUGS as readonly string[]).includes(input.slug)) {
    return {
      allowed: false, reasonCode: "WIRELESS_ACTIVE_TOOL_BLOCKED",
      reason: `${input.slug} has no executing adapter in this build (§21/§22): active wireless tooling exists only as a governed lab architecture (§65)`,
    };
  }
  return { allowed: true };
}

// ── Lab validation (§65/§66) ────────────────────────────────────────

export interface WirelessLabRequest {
  environmentKind: string; // must be LAB
  dedicatedTestAp: boolean;
  dedicatedTestClients: boolean;
  authorizationId?: string;
  approved: boolean;
  requestedDurationSeconds: number;
  killSwitchEngaged: boolean;
  /** §66: only synthetic/test credentials — checked by PRESENCE of a
   *  synthetic marker, never by storing a value. */
  syntheticCredentialsOnly: boolean;
}

export type WirelessLabDecision =
  | { status: "ELIGIBLE_NOT_PROVISIONED"; reasons: string[] }
  | { status: "BLOCKED"; reasonCode: string; reasons: string[] };

export const WIRELESS_LAB_HARD_TIMEOUT_SECONDS = 1800;

/** §65: the governed lab gate. Every requirement is checked; when
 *  all pass, the honest result is ELIGIBLE_NOT_PROVISIONED — the lab
 *  transport/active tooling is deliberately unwired in this build,
 *  so nothing is ever transmitted on the strength of this check. */
export function evaluateWirelessLabPolicy(req: WirelessLabRequest): WirelessLabDecision {
  const reasons: string[] = [];
  if (req.environmentKind !== "LAB") reasons.push("lab validation requires an explicit LAB environment (§65)");
  if (!req.dedicatedTestAp) reasons.push("a dedicated test AP is required (§65)");
  if (!req.dedicatedTestClients) reasons.push("dedicated test clients are required (§65)");
  if (!req.authorizationId) reasons.push("an authorization record is required (§65)");
  if (!req.approved) reasons.push("a separate approval is required (§65)");
  if (req.killSwitchEngaged) reasons.push("the validation kill switch is engaged (§65)");
  if (req.requestedDurationSeconds <= 0 || req.requestedDurationSeconds > WIRELESS_LAB_HARD_TIMEOUT_SECONDS) {
    reasons.push(`duration must be within the ${WIRELESS_LAB_HARD_TIMEOUT_SECONDS}s hard timeout (§65)`);
  }
  if (!req.syntheticCredentialsOnly) reasons.push("only synthetic/test Wi-Fi credentials may be used — real employee/customer passwords are never stored or cracked (§66)");
  if (reasons.length > 0) return { status: "BLOCKED", reasonCode: "WIRELESS_LAB_REQUIREMENTS_UNMET", reasons };
  return {
    status: "ELIGIBLE_NOT_PROVISIONED",
    reasons: ["all §65 requirements are met, but no WIRELESS_LAB_VALIDATION sensor transport is provisioned in this build — the request is recorded, never executed against any network"],
  };
}
