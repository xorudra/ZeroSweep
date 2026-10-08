import type { DetectionRuleDefinition } from "./dsl";

/**
 * Detection rule templates (Prompt 28 §25/§26). Defensive patterns
 * over DSRclone's own telemetry. ATT&CK mappings are CLASSIFICATION
 * CONTEXT ONLY (§27): they label what a detection resembles; they
 * never drive any automated action.
 */

export interface AttackMapping {
  framework: "MITRE_ATTACK";
  frameworkVersion: string;
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  subTechniqueId?: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
}

export interface DetectionTemplate {
  key: string;
  name: string;
  description: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  definition: DetectionRuleDefinition;
  attack: AttackMapping[];
  dataSources: string[];
}

const cond = (field: string, op: string, value?: unknown) => ({ kind: "cond" as const, field, op: op as never, value });
const all = (...children: unknown[]) => ({ kind: "all" as const, children: children as never[] });

const ATTACK_VERSION = "15.1";
const map = (tactic: string, techniqueId: string, techniqueName: string, confidence: "LOW" | "MEDIUM" | "HIGH", subTechniqueId?: string): AttackMapping =>
  ({ framework: "MITRE_ATTACK", frameworkVersion: ATTACK_VERSION, tactic, techniqueId, techniqueName, subTechniqueId, confidence });

export const DETECTION_TEMPLATES: readonly DetectionTemplate[] = [
  {
    key: "auth-failure-burst", name: "Authentication failure burst",
    description: "Multiple failed authentication attempts for one identity in a short window (brute-force / password-spray indicator).",
    category: "AUTHENTICATION", severity: "HIGH",
    definition: { type: "THRESHOLD", windowSeconds: 300, threshold: { count: 5, groupBy: "identityReference" },
      conditions: all(cond("eventCategory", "eq", "AUTHENTICATION"), cond("attributes.outcome", "eq", "FAILURE")) },
    attack: [map("Credential Access", "T1110", "Brute Force", "MEDIUM")],
    dataSources: ["AUTHENTICATION"],
  },
  {
    key: "privilege-change", name: "Suspicious privilege change",
    description: "A role grant or privilege escalation event on an identity.",
    category: "IDENTITY", severity: "HIGH",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventCategory", "eq", "IDENTITY"), cond("eventAction", "in", ["ROLE_GRANTED", "PRIVILEGE_ESCALATED", "ADMIN_ROLE_ASSIGNED"])) },
    attack: [map("Persistence", "T1098", "Account Manipulation", "MEDIUM")],
    dataSources: ["AUTHENTICATION", "DSRCLONE_INTERNAL"],
  },
  {
    key: "unexpected-admin-access", name: "Unexpected administrative access",
    description: "Administrative access flagged unexpected by the source (new device/location/context).",
    category: "IDENTITY", severity: "HIGH",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "eq", "ADMIN_ACCESS"), cond("attributes.unexpected", "eq", true)) },
    attack: [map("Defense Evasion", "T1078", "Valid Accounts", "LOW")],
    dataSources: ["AUTHENTICATION"],
  },
  {
    key: "new-privileged-service-account", name: "New privileged service account",
    description: "A service account was created with privileged scope.",
    category: "IDENTITY", severity: "MEDIUM",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "eq", "SERVICE_ACCOUNT_CREATED"), cond("attributes.privileged", "eq", true)) },
    attack: [map("Persistence", "T1136", "Create Account", "MEDIUM")],
    dataSources: ["DSRCLONE_INTERNAL", "CLOUD"],
  },
  {
    key: "api-key-misuse", name: "API-key misuse indicators",
    description: "Repeated API-key authentication failures from platform integrations.",
    category: "API", severity: "HIGH",
    definition: { type: "THRESHOLD", windowSeconds: 600, threshold: { count: 10, groupBy: "attributes.sourceIp" },
      conditions: all(cond("eventAction", "eq", "API_KEY_AUTH_FAILURE")) },
    attack: [map("Credential Access", "T1110", "Brute Force", "LOW")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "security-policy-change", name: "Security policy change",
    description: "A workspace security policy was modified.",
    category: "POLICY", severity: "MEDIUM",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventCategory", "eq", "POLICY"), cond("eventAction", "in", ["POLICY_UPDATED", "POLICY_CREATED", "POLICY_DELETED"])) },
    attack: [map("Defense Evasion", "T1562", "Impair Defenses", "LOW")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "critical-control-disabled", name: "Critical control disabled",
    description: "A security control was disabled or enforcement was turned off.",
    category: "POLICY", severity: "CRITICAL",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "in", ["CONTROL_DISABLED", "ENFORCEMENT_DISABLED", "MFA_ENFORCEMENT_DISABLED"])) },
    attack: [map("Defense Evasion", "T1562", "Impair Defenses", "MEDIUM", "T1562.001")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "public-exposure-change", name: "Public exposure change",
    description: "An asset became publicly exposed or its exposure materially changed.",
    category: "EXPOSURE", severity: "HIGH",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "eq", "EXPOSURE_CHANGED"), cond("attributes.public", "eq", true)) },
    attack: [map("Initial Access", "T1133", "External Remote Services", "LOW")],
    dataSources: ["CLOUD", "DSRCLONE_INTERNAL"],
  },
  {
    key: "new-kev-exposure", name: "New KEV exposure",
    description: "A finding matched the CISA KEV catalog on a platform asset.",
    category: "VULNERABILITY", severity: "CRITICAL",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "eq", "KEV_MATCHED")) },
    attack: [map("Initial Access", "T1190", "Exploit Public-Facing Application", "MEDIUM")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "critical-vuln-critical-asset", name: "Critical vulnerability on critical asset",
    description: "A CRITICAL finding landed on a CRITICAL-criticality asset.",
    category: "VULNERABILITY", severity: "CRITICAL",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventCategory", "eq", "FINDING"), cond("severity", "eq", "CRITICAL"), cond("attributes.assetCriticality", "eq", "CRITICAL")) },
    attack: [map("Initial Access", "T1190", "Exploit Public-Facing Application", "LOW")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "gate-bypass-attempt", name: "DevSecOps gate bypass attempt",
    description: "A pipeline attempted to bypass or override a security gate.",
    category: "DEVSECOPS", severity: "HIGH",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "in", ["GATE_BYPASS_ATTEMPT", "GATE_OVERRIDE_ATTEMPT"])) },
    attack: [map("Initial Access", "T1195", "Supply Chain Compromise", "LOW", "T1195.002")],
    dataSources: ["DEVSECOPS"],
  },
  {
    key: "scanner-scope-violation", name: "Scanner scope violation",
    description: "A scanner attempted to touch an out-of-scope target (platform safety signal).",
    category: "PLATFORM_SAFETY", severity: "HIGH",
    definition: { type: "SINGLE_EVENT",
      conditions: all(cond("eventAction", "eq", "SCOPE_VIOLATION")) },
    attack: [map("Reconnaissance", "T1595", "Active Scanning", "LOW")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "invalid-webhook-burst", name: "Invalid webhook signature burst",
    description: "Repeated invalid webhook signatures against one source.",
    category: "INTEGRATION", severity: "MEDIUM",
    definition: { type: "THRESHOLD", windowSeconds: 300, threshold: { count: 10, groupBy: "source" },
      conditions: all(cond("eventAction", "eq", "WEBHOOK_INVALID_SIGNATURE")) },
    attack: [map("Initial Access", "T1071", "Application Layer Protocol", "LOW", "T1071.001")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "secret-access-failures", name: "Repeated secret-access failures",
    description: "Repeated denied attempts to access secrets/credentials.",
    category: "CREDENTIAL", severity: "HIGH",
    definition: { type: "THRESHOLD", windowSeconds: 600, threshold: { count: 3, groupBy: "identityReference" },
      conditions: all(cond("eventAction", "eq", "SECRET_ACCESS_DENIED")) },
    attack: [map("Credential Access", "T1552", "Unsecured Credentials", "MEDIUM")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "integration-credential-failure", name: "Unexpected integration credential failure",
    description: "Repeated authentication failures from one integration.",
    category: "INTEGRATION", severity: "MEDIUM",
    definition: { type: "THRESHOLD", windowSeconds: 900, threshold: { count: 3, groupBy: "source" },
      conditions: all(cond("eventAction", "eq", "INTEGRATION_AUTH_FAILURE")) },
    attack: [map("Defense Evasion", "T1078", "Valid Accounts", "LOW")],
    dataSources: ["DSRCLONE_INTERNAL"],
  },
  {
    key: "privilege-then-sensitive-access", name: "Privilege change followed by sensitive access",
    description: "Sequence: authentication anomaly → privilege change → sensitive-resource access within one hour (defensive correlation).",
    category: "CORRELATION", severity: "CRITICAL",
    definition: { type: "SEQUENCE", windowSeconds: 3600,
      conditions: all(cond("eventCategory", "exists")),
      sequence: [
        all(cond("eventCategory", "eq", "AUTHENTICATION"), cond("attributes.unexpected", "eq", true)),
        all(cond("eventAction", "in", ["ROLE_GRANTED", "PRIVILEGE_ESCALATED"])),
        all(cond("eventAction", "eq", "SENSITIVE_RESOURCE_ACCESS")),
      ] },
    attack: [map("Privilege Escalation", "T1078", "Valid Accounts", "MEDIUM")],
    dataSources: ["AUTHENTICATION", "DSRCLONE_INTERNAL"],
  },
] as const;

export function getDetectionTemplate(key: string): DetectionTemplate | null {
  return DETECTION_TEMPLATES.find((t) => t.key === key) ?? null;
}
