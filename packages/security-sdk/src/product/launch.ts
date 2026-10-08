/**
 * v1.0 launch gates (Prompt 40 §264–§272) and demo mode (§176–§180).
 *
 * Gate honesty rules:
 *  - A gate is PASS only on recorded evidence.
 *  - Billing gate is NOT_APPLICABLE when no billing provider is
 *    configured — never a fake PASS (§268).
 *  - License gate is NOT_APPLICABLE when self-hosted licensing is not
 *    enabled (§269).
 *  - V1_READY requires every APPLICABLE mandatory gate to PASS (§271);
 *    any applicable failure yields V1_BLOCKED with the exact failure
 *    (§272). Nothing here can be overridden by subscription tier (§298).
 */

export const LAUNCH_GATES = [
  "RC_SECURITY",
  "TENANT_ISOLATION",
  "AUTHORIZATION",
  "PRODUCT_ENTITLEMENT",
  "QUOTA",
  "METERING",
  "BILLING_SECURITY",
  "LICENSE_SECURITY",
  "ONBOARDING",
  "BACKUP",
  "RESTORE",
  "PRODUCTION_DEPLOYMENT",
  "DOCUMENTATION",
  "NO_BLOCKER_DEFECTS",
] as const;
export type LaunchGate = (typeof LAUNCH_GATES)[number];

export type GateOutcome = "PASS" | "FAIL" | "NOT_APPLICABLE";

export interface LaunchGateResult {
  gate: LaunchGate;
  outcome: GateOutcome;
  evidence: string;
}

export interface LaunchGateInputs {
  outcomes: Partial<Record<LaunchGate, { outcome: "PASS" | "FAIL"; evidence: string }>>;
  billingConfigured: boolean;
  selfHostedLicensingEnabled: boolean;
}

export interface LaunchEvaluation {
  status: "V1_READY" | "V1_BLOCKED";
  gates: LaunchGateResult[];
  blockers: string[];
}

export function evaluateLaunchGates(inputs: LaunchGateInputs): LaunchEvaluation {
  const gates: LaunchGateResult[] = LAUNCH_GATES.map((gate) => {
    if (gate === "BILLING_SECURITY" && !inputs.billingConfigured) {
      return { gate, outcome: "NOT_APPLICABLE" as const, evidence: "No billing provider configured (§268): billing is disabled, not simulated." };
    }
    if (gate === "LICENSE_SECURITY" && !inputs.selfHostedLicensingEnabled) {
      return { gate, outcome: "NOT_APPLICABLE" as const, evidence: "Self-hosted licensing not enabled in this deployment (§269)." };
    }
    const recorded = inputs.outcomes[gate];
    if (!recorded) {
      return { gate, outcome: "FAIL" as const, evidence: "No evidence recorded for this gate; an unmeasured gate cannot pass (§297)." };
    }
    return { gate, outcome: recorded.outcome, evidence: recorded.evidence };
  });
  const blockers = gates.filter((g) => g.outcome === "FAIL").map((g) => `${g.gate}: ${g.evidence}`);
  return { status: blockers.length === 0 ? "V1_READY" : "V1_BLOCKED", gates, blockers };
}

// ---------------------------------------------------------------------------
// Demo mode (§176–§180)
// ---------------------------------------------------------------------------

/**
 * Demo data is synthetic and labelled as such everywhere it appears.
 * Demo organizations can NEVER start real scans (§178/§228): demo mode
 * exists for evaluation of the product surface only.
 */
export const DEMO_DATA_LABEL = "SYNTHETIC_DEMO_DATA";

export interface DemoDataset {
  label: typeof DEMO_DATA_LABEL;
  assets: Array<{ name: string; type: string }>;
  findings: Array<{ title: string; severity: string }>;
  scanHistory: Array<{ profile: string; status: string }>;
}

export function buildDemoDataset(): DemoDataset {
  return {
    label: DEMO_DATA_LABEL,
    assets: [
      { name: "demo-shop.example", type: "DOMAIN" },
      { name: "demo-api.example", type: "API" },
    ],
    findings: [
      { title: "[DEMO] Example TLS configuration finding (synthetic)", severity: "LOW" },
      { title: "[DEMO] Example missing security header (synthetic)", severity: "INFORMATIONAL" },
    ],
    scanHistory: [{ profile: "SAFE_STANDARD", status: "COMPLETED_SYNTHETIC" }],
  };
}

/** §178/§180: demo organizations have no credentials and no real scanning. */
export function demoModeAllows(action: "VIEW" | "START_SCAN" | "CONNECT_INTEGRATION"): boolean {
  return action === "VIEW";
}

export const RELEASE_CHANNELS = ["STABLE", "RC", "BETA", "NIGHTLY"] as const;
export type ReleaseChannel = (typeof RELEASE_CHANNELS)[number];
