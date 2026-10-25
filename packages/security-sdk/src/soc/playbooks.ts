/**
 * Incident response playbooks (Prompt 28 §83–§89). Playbooks are
 * DECLARATIVE step lists drawn from a closed category set. There is
 * no step type that executes code (§85/§150): a step can investigate,
 * enrich, notify, ticket, request approval, run an ALREADY-APPROVED
 * predefined response action, wait, verify or document — nothing else.
 */

export const PLAYBOOK_STEP_CATEGORIES = [
  "INVESTIGATE", "ENRICH", "NOTIFY", "CREATE_TICKET", "REQUEST_APPROVAL",
  "EXECUTE_APPROVED_RESPONSE", "WAIT", "VERIFY", "DOCUMENT",
] as const;
export type PlaybookStepCategory = (typeof PLAYBOOK_STEP_CATEGORIES)[number];

export interface PlaybookStep {
  key: string;
  title: string;
  category: PlaybookStepCategory;
  description: string;
  responseActionKey?: string; // only for EXECUTE_APPROVED_RESPONSE
  waitMinutes?: number; // only for WAIT (bounded)
}

export interface PlaybookTemplate {
  key: string;
  title: string;
  version: number;
  description: string;
  steps: PlaybookStep[];
}

const MAX_WAIT_MINUTES = 7 * 24 * 60;

export function validatePlaybookSteps(steps: unknown): { ok: boolean; errors: string[]; steps?: PlaybookStep[] } {
  const errors: string[] = [];
  if (!Array.isArray(steps) || steps.length === 0 || steps.length > 40) return { ok: false, errors: ["PLAYBOOK_STEPS_INVALID"] };
  const out: PlaybookStep[] = [];
  const seen = new Set<string>();
  for (const raw of steps) {
    if (!raw || typeof raw !== "object") { errors.push("PLAYBOOK_STEP_INVALID"); continue; }
    const s = raw as Record<string, unknown>;
    // §85: any executable-shaped field rejects the whole playbook.
    for (const forbidden of ["command", "shell", "script", "code", "sql", "eval", "http", "url", "expression"]) {
      if (forbidden in s) errors.push(`PLAYBOOK_STEP_FORBIDDEN_FIELD:${forbidden}`);
    }
    if (typeof s.key !== "string" || typeof s.title !== "string" || typeof s.description !== "string") { errors.push("PLAYBOOK_STEP_FIELDS_MISSING"); continue; }
    if (seen.has(s.key)) errors.push(`PLAYBOOK_STEP_DUPLICATE:${s.key}`);
    seen.add(s.key);
    if (!(PLAYBOOK_STEP_CATEGORIES as readonly string[]).includes(s.category as string)) { errors.push(`PLAYBOOK_STEP_CATEGORY_UNKNOWN:${String(s.category)}`); continue; }
    const step: PlaybookStep = { key: s.key, title: s.title, category: s.category as PlaybookStepCategory, description: s.description };
    if (s.category === "EXECUTE_APPROVED_RESPONSE") {
      if (typeof s.responseActionKey !== "string" || s.responseActionKey.length === 0) errors.push("PLAYBOOK_RESPONSE_STEP_NEEDS_ACTION");
      else step.responseActionKey = s.responseActionKey;
    }
    if (s.category === "WAIT") {
      if (typeof s.waitMinutes !== "number" || s.waitMinutes < 1 || s.waitMinutes > MAX_WAIT_MINUTES) errors.push("PLAYBOOK_WAIT_OUT_OF_BOUNDS");
      else step.waitMinutes = s.waitMinutes;
    }
    out.push(step);
  }
  return errors.length > 0 ? { ok: false, errors: [...new Set(errors)] } : { ok: true, errors: [], steps: out };
}

function steps(...defs: Array<[string, string, PlaybookStepCategory, string, Partial<PlaybookStep>?]>): PlaybookStep[] {
  return defs.map(([key, title, category, description, extra]) => ({ key, title, category, description, ...(extra ?? {}) }));
}

export const PLAYBOOK_TEMPLATES: readonly PlaybookTemplate[] = [
  {
    key: "suspected-credential-compromise", title: "Suspected Credential Compromise", version: 1,
    description: "Triage and contain a suspected compromised credential using predefined ZeroSweep actions only.",
    steps: steps(
      ["confirm", "Confirm the signal", "INVESTIGATE", "Review the triggering alerts, events and indicator context."],
      ["scope", "Scope affected identities and assets", "ENRICH", "Pull asset/identity/finding context from the platform graph."],
      ["notify-owner", "Notify the credential owner", "NOTIFY", "Send a notification through the notification router."],
      ["approve-revoke", "Approve session revocation", "REQUEST_APPROVAL", "A second analyst approves containment for high-impact targets."],
      ["revoke-session", "Revoke the session", "EXECUTE_APPROVED_RESPONSE", "Revoke the ZeroSweep session via the approved response action.", { responseActionKey: "REVOKE_DSRCLONE_SESSION" }],
      ["rotate", "Request credential rotation", "EXECUTE_APPROVED_RESPONSE", "Create a tracked rotation request for the owner.", { responseActionKey: "REQUEST_CREDENTIAL_ROTATION" }],
      ["verify", "Verify containment", "VERIFY", "Confirm no further suspicious events for the identity in the observation window."],
      ["document", "Document outcome", "DOCUMENT", "Record findings and open questions on the incident timeline."],
    ),
  },
  {
    key: "critical-internet-facing-vulnerability", title: "Critical Internet-Facing Vulnerability", version: 1,
    description: "A KEV/critical finding on an internet-exposed critical asset.",
    steps: steps(
      ["confirm", "Confirm exposure and KEV status", "INVESTIGATE", "Verify the finding, asset exposure and KEV listing from platform records."],
      ["ticket", "Create remediation ticket", "CREATE_TICKET", "Open the tracked remediation ticket."],
      ["notify", "Notify asset owner", "NOTIFY", "Notify the owning team with the SLA target."],
      ["verify-fix", "Verify remediation", "VERIFY", "Confirm the retest/rescan result before closure."],
      ["document", "Document outcome", "DOCUMENT", "Record the timeline and residual risk."],
    ),
  },
  {
    key: "exposed-secret", title: "Exposed Secret", version: 1,
    description: "A secret exposure detected in code, artifacts or telemetry.",
    steps: steps(
      ["confirm", "Confirm the exposure", "INVESTIGATE", "Confirm the secret class and location from redacted metadata only."],
      ["rotate", "Request rotation", "EXECUTE_APPROVED_RESPONSE", "Request rotation from the owning team.", { responseActionKey: "REQUEST_CREDENTIAL_ROTATION" }],
      ["ticket", "Create remediation ticket", "CREATE_TICKET", "Track removal of the exposed secret."],
      ["verify", "Verify removal", "VERIFY", "Confirm the secret no longer appears in scans."],
      ["document", "Document outcome", "DOCUMENT", "Record scope and follow-ups."],
    ),
  },
  {
    key: "suspicious-privileged-login", title: "Suspicious Privileged Login", version: 1,
    description: "Privileged identity authentication anomaly.",
    steps: steps(
      ["confirm", "Confirm the anomaly", "INVESTIGATE", "Review authentication events and identity context."],
      ["enrich", "Enrich with threat intelligence", "ENRICH", "Check source indicators against the workspace intel store."],
      ["approve", "Approve containment", "REQUEST_APPROVAL", "Approval for session revocation on a privileged identity."],
      ["revoke", "Revoke session", "EXECUTE_APPROVED_RESPONSE", "Revoke the ZeroSweep session.", { responseActionKey: "REVOKE_DSRCLONE_SESSION" }],
      ["verify", "Verify", "VERIFY", "Confirm no continued anomalous access."],
      ["document", "Document outcome", "DOCUMENT", "Record the investigation summary."],
    ),
  },
  {
    key: "cloud-security-incident", title: "Cloud Security Incident", version: 1,
    description: "Cloud posture/exposure incident from cloud security findings.",
    steps: steps(
      ["confirm", "Confirm the cloud signal", "INVESTIGATE", "Review cloud findings, drift and exposure records."],
      ["mark-asset", "Mark asset for review", "EXECUTE_APPROVED_RESPONSE", "Flag the cloud asset for owner review.", { responseActionKey: "MARK_ASSET_FOR_REVIEW" }],
      ["ticket", "Create remediation ticket", "CREATE_TICKET", "Track the cloud remediation."],
      ["verify", "Verify posture", "VERIFY", "Confirm the posture re-assessment result."],
      ["document", "Document outcome", "DOCUMENT", "Record impact and follow-ups."],
    ),
  },
  {
    key: "devsecops-gate-incident", title: "DevSecOps Security Gate Incident", version: 1,
    description: "A security gate bypass attempt or repeated gate failure.",
    steps: steps(
      ["confirm", "Confirm the gate event", "INVESTIGATE", "Review pipeline events and the gate evaluation record."],
      ["pause", "Pause scan automation if needed", "EXECUTE_APPROVED_RESPONSE", "Pause automation pending review (approval-gated action).", { responseActionKey: "PAUSE_SCAN_AUTOMATION" }],
      ["ticket", "Create remediation ticket", "CREATE_TICKET", "Track the pipeline fix."],
      ["verify", "Verify gate integrity", "VERIFY", "Confirm gates evaluate correctly on a test run."],
      ["document", "Document outcome", "DOCUMENT", "Record the bypass path and control fix."],
    ),
  },
  {
    key: "malicious-indicator-match", title: "Malicious Indicator Match", version: 1,
    description: "Telemetry matched a threat-intelligence indicator.",
    steps: steps(
      ["confirm", "Confirm the match context", "INVESTIGATE", "Review the indicator provenance, confidence and matched events."],
      ["enrich", "Enrich affected entities", "ENRICH", "Pull asset/identity context for every matched entity."],
      ["notify", "Notify responders", "NOTIFY", "Notify the SOC channel through the router."],
      ["verify", "Verify scope", "VERIFY", "Confirm whether additional assets matched the indicator."],
      ["document", "Document outcome", "DOCUMENT", "Record confidence, provenance and disposition."],
    ),
  },
] as const;

export function getPlaybookTemplate(key: string): PlaybookTemplate | null {
  return PLAYBOOK_TEMPLATES.find((p) => p.key === key) ?? null;
}
