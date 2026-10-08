import { describe, expect, it } from "vitest";
import {
  canRemediationTransition, evaluateRemediationTransition,
  resolveRemediationOwnership as resolveOwnership, resolveRemediationSla, deriveSlaState, evaluateSlaRecalculation,
  verificationPolicyFor, isVerificationMethodAllowed, evaluateVerification, isHighRiskRemediation,
  buildTicketPayload, workItemIdempotencyKey, isWorkItemStale,
  computeCampaignProgress, findingMatchesCampaignScope,
  computeRemediationMetrics, fixDurabilityHours, translateRemediationQuery,
  type RemediationSlaPolicyView,
} from "./index";

describe("remediation state machine (§6/§7)", () => {
  it("allows the governed happy path", () => {
    expect(canRemediationTransition("NEW", "TRIAGED")).toBe(true);
    expect(canRemediationTransition("IN_PROGRESS", "FIX_CLAIMED")).toBe(true);
    expect(canRemediationTransition("VERIFICATION_RUNNING", "VERIFIED_FIXED")).toBe(true);
    expect(canRemediationTransition("VERIFIED_FIXED", "CLOSED")).toBe(true);
  });

  it("§133: NEW → CLOSED is rejected", () => {
    const v = evaluateRemediationTransition({ from: "NEW", to: "CLOSED" });
    expect(v.ok).toBe(false);
    expect(v.error).toContain("not allowed");
  });

  it("§7: NEW → VERIFIED_FIXED fails even before the verification guard", () => {
    const v = evaluateRemediationTransition({ from: "NEW", to: "VERIFIED_FIXED", viaVerification: true });
    expect(v.ok).toBe(false);
  });

  it("VERIFIED_FIXED requires the verification path (§61)", () => {
    expect(evaluateRemediationTransition({ from: "VERIFICATION_RUNNING", to: "VERIFIED_FIXED" }).ok).toBe(false);
    expect(evaluateRemediationTransition({ from: "VERIFICATION_RUNNING", to: "VERIFIED_FIXED", viaVerification: true }).ok).toBe(true);
  });

  it("FIX_CLAIMED requires a recorded claim (§50)", () => {
    expect(evaluateRemediationTransition({ from: "IN_PROGRESS", to: "FIX_CLAIMED" }).ok).toBe(false);
    expect(evaluateRemediationTransition({ from: "IN_PROGRESS", to: "FIX_CLAIMED", viaFixClaim: true }).ok).toBe(true);
  });

  it("FALSE_POSITIVE requires reason + evidence (§12)", () => {
    expect(evaluateRemediationTransition({ from: "TRIAGED", to: "FALSE_POSITIVE" }).ok).toBe(false);
    expect(evaluateRemediationTransition({ from: "TRIAGED", to: "FALSE_POSITIVE", reason: "not exploitable" }).ok).toBe(false);
    expect(evaluateRemediationTransition({ from: "TRIAGED", to: "FALSE_POSITIVE", reason: "not exploitable", evidence: { note: "banner only" } }).ok).toBe(true);
  });

  it("ACCEPTED_RISK requires an approved exception (§78)", () => {
    expect(evaluateRemediationTransition({ from: "TRIAGED", to: "ACCEPTED_RISK" }).ok).toBe(false);
    expect(evaluateRemediationTransition({ from: "TRIAGED", to: "ACCEPTED_RISK", viaException: true }).ok).toBe(true);
  });

  it("CLOSED from VERIFIED_FIXED requires the closure engine (§68)", () => {
    expect(evaluateRemediationTransition({ from: "VERIFIED_FIXED", to: "CLOSED" }).ok).toBe(false);
    expect(evaluateRemediationTransition({ from: "VERIFIED_FIXED", to: "CLOSED", viaClosure: true }).ok).toBe(true);
  });
});

describe("ownership resolution (§14–§17)", () => {
  it("follows the deterministic priority chain with confidence", () => {
    const both = resolveOwnership({
      assetOwner: { ownerType: "ASSET_OWNER", ownerId: "asset-1" },
      applicationOwner: { ownerType: "APPLICATION_OWNER", ownerId: "app-1" },
    });
    expect(both.ownerId).toBe("app-1");
    expect(both.confidence).toBe("HIGH");
    const explicit = resolveOwnership({
      explicitAssignment: { ownerType: "USER", ownerId: "u-1" },
      applicationOwner: { ownerType: "APPLICATION_OWNER", ownerId: "app-1" },
    });
    expect(explicit).toMatchObject({ ownerId: "u-1", confidence: "VERIFIED", source: "EXPLICIT_FINDING_ASSIGNMENT" });
    const fallback = resolveOwnership({ workspaceDefaultTeam: { ownerType: "TEAM", teamId: "t-1" } });
    expect(fallback).toMatchObject({ teamId: "t-1", confidence: "LOW" });
  });

  it("never invents an owner", () => {
    const none = resolveOwnership({});
    expect(none.confidence).toBe("UNKNOWN");
    expect(none.ownerId).toBeUndefined();
  });
});

const policy = (over: Partial<RemediationSlaPolicyView>): RemediationSlaPolicyView => ({
  id: "pol-1", name: "default", version: 3, isDefault: true, active: true,
  rules: { P0: 24, P1: 48, P2: 168, P3: 720, P4: 2160 },
  conditions: null, warningThresholds: null, escalation: null,
  verificationRequired: true, requiredCleanObservations: 1, ...over,
});

describe("SLA resolution (§21–§24)", () => {
  it("§134: a KEV-conditioned policy wins over the default and snapshots version + target", () => {
    const kevPolicy = policy({
      id: "pol-kev", name: "kev", isDefault: false, version: 7,
      conditions: { kevOnly: true, targetHours: 24, requiredCleanObservations: 2 },
    });
    const resolved = resolveRemediationSla([policy({}), kevPolicy], {
      priority: "P2", severity: "HIGH", kevListed: true, internetExposed: true, assetCriticality: "CRITICAL",
    });
    expect(resolved?.policyId).toBe("pol-kev");
    expect(resolved?.policyVersion).toBe(7);
    expect(resolved?.targetHours).toBe(24);
    expect(resolved?.requiredCleanObservations).toBe(2);
    const nonKev = resolveRemediationSla([policy({}), kevPolicy], {
      priority: "P2", severity: "HIGH", kevListed: false, internetExposed: false,
    });
    expect(nonKev?.policyId).toBe("pol-1");
    expect(nonKev?.targetHours).toBe(168);
  });

  it("returns null instead of inventing a due date", () => {
    expect(resolveRemediationSla([], { severity: "LOW", kevListed: false, internetExposed: false })).toBeNull();
  });
});

describe("SLA clock (§26/§27/§136)", () => {
  const start = new Date("2026-10-01T00:00:00Z");
  const due = new Date(start.getTime() + 24 * 3600 * 1000);
  const snap = { startedAt: start, dueAt: due, pausedDurationMs: 0, pausedAt: null, completedAt: null, state: "ON_TRACK" as const, warningPct: 0.5, atRiskPct: 0.8 };

  it("derives WARNING / AT_RISK from elapsed fraction", () => {
    expect(deriveSlaState(snap, new Date(start.getTime() + 13 * 3600 * 1000)).state).toBe("WARNING");
    expect(deriveSlaState(snap, new Date(start.getTime() + 20 * 3600 * 1000)).state).toBe("AT_RISK");
  });

  it("§136: past dueAt → BREACHED", () => {
    expect(deriveSlaState(snap, new Date(start.getTime() + 25 * 3600 * 1000)).state).toBe("BREACHED");
  });

  it("paused time does not count against the target", () => {
    const paused = { ...snap, pausedAt: new Date(start.getTime() + 2 * 3600 * 1000) };
    expect(deriveSlaState(paused, new Date(start.getTime() + 100 * 3600 * 1000)).state).toBe("PAUSED");
    const resumed = { ...snap, pausedDurationMs: 10 * 3600 * 1000 };
    expect(deriveSlaState(resumed, new Date(start.getTime() + 25 * 3600 * 1000)).state).not.toBe("BREACHED");
  });

  it("§25: recalculation never silently shortens", () => {
    const r = evaluateSlaRecalculation({ currentDueAt: due, proposedDueAt: new Date(due.getTime() - 3600e3), allowShorten: false });
    expect(r.applied).toBe(false);
    expect(r.dueAt).toEqual(due);
    const ext = evaluateSlaRecalculation({ currentDueAt: due, proposedDueAt: new Date(due.getTime() + 3600e3), allowShorten: false });
    expect(ext.applied).toBe(true);
  });
});

describe("verification evaluation (§52–§67)", () => {
  it("§140: scanner error is ERROR — never PASSED", () => {
    const e = evaluateVerification({ observation: { scannerStatus: "ERROR", stillPresent: false, evidenceSufficient: true }, previousCleanObservations: 5, requiredCleanObservations: 1 });
    expect(e.outcome).toBe("ERROR");
    expect(e.caseEffect).toBe("NONE");
  });

  it("§141: insufficient evidence is INCONCLUSIVE and closes nothing", () => {
    const e = evaluateVerification({ observation: { scannerStatus: "OK", stillPresent: null, evidenceSufficient: false }, previousCleanObservations: 0, requiredCleanObservations: 1 });
    expect(e.outcome).toBe("INCONCLUSIVE");
    expect(e.caseEffect).toBe("STAY_PENDING");
  });

  it("§139: still present → FAILED, back to actionable", () => {
    const e = evaluateVerification({ observation: { scannerStatus: "OK", stillPresent: true, evidenceSufficient: true }, previousCleanObservations: 0, requiredCleanObservations: 1 });
    expect(e.outcome).toBe("FAILED");
    expect(e.caseEffect).toBe("RETURN_TO_ACTIONABLE");
  });

  it("§142: multi-observation confirmation — first clean stays pending, second verifies", () => {
    const first = evaluateVerification({ observation: { scannerStatus: "OK", stillPresent: false, evidenceSufficient: true }, previousCleanObservations: 0, requiredCleanObservations: 2 });
    expect(first.outcome).toBe("PENDING_CONFIRMATION");
    const second = evaluateVerification({ observation: { scannerStatus: "OK", stillPresent: false, evidenceSufficient: true }, previousCleanObservations: first.cleanObservations, requiredCleanObservations: 2 });
    expect(second.outcome).toBe("PASSED");
    expect(second.caseEffect).toBe("VERIFIED_FIXED");
  });

  it("policy maps categories to methods (§54)", () => {
    expect(isVerificationMethodAllowed("sca dependency", "SBOM_REEVALUATION")).toBe(true);
    expect(isVerificationMethodAllowed("sca dependency", "CLOUD_POSTURE_RECHECK")).toBe(false);
    expect(verificationPolicyFor("web").methods).toContain("TARGETED_RETEST");
    expect(isHighRiskRemediation({ priority: "P3", severity: "HIGH", kevListed: true })).toBe(true);
    expect(isHighRiskRemediation({ priority: "P3", severity: "HIGH", kevListed: false })).toBe(false);
  });
});

describe("ticket payload + redaction (§43–§46)", () => {
  it("§147: a synthetic secret in the title/body is scrubbed from the payload", () => {
    const payload = buildTicketPayload({
      caseId: "case-1",
      finding: {
        id: "f-1", title: "Leaked key AKIAIOSFODNN7EXAMPLE in config", severity: "HIGH", priority: "P1",
        host: "api.example.com", cve: "CVE-2026-0001", cwe: "CWE-798",
        riskExplanation: "credential exposure", remediationSummary: "rotate the key",
      },
      dueAt: new Date("2026-10-09T00:00:00Z"),
    });
    expect(payload.title).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(payload.body).toContain("CVE-2026-0001");
    expect(payload.dsrcloneRef).toBe("case-1");
    expect(payload.redactions.length).toBeGreaterThan(0);
  });

  it("idempotency key is stable per case+provider (§46)", () => {
    expect(workItemIdempotencyKey("c1", "JIRA")).toBe(workItemIdempotencyKey("c1", "jira"));
    expect(workItemIdempotencyKey("c1", "JIRA")).not.toBe(workItemIdempotencyKey("c2", "JIRA"));
  });

  it("staleness applies only to live tickets (§39)", () => {
    const now = new Date("2026-10-09T00:00:00Z");
    expect(isWorkItemStale({ status: "SYNCED", lastSyncedAt: new Date("2026-09-01T00:00:00Z"), createdAt: now }, now)).toBe(true);
    expect(isWorkItemStale({ status: "FAILED", lastSyncedAt: null, createdAt: new Date("2026-09-01T00:00:00Z") }, now)).toBe(false);
  });
});

describe("campaigns (§87–§91/§152)", () => {
  it("progress is computed from live case states", () => {
    const now = new Date("2026-10-08T00:00:00Z");
    const p = computeCampaignProgress([
      { status: "IN_PROGRESS", dueAt: new Date("2026-10-20T00:00:00Z") },
      { status: "VERIFIED_FIXED", dueAt: new Date("2026-10-20T00:00:00Z") },
      { status: "NEW", dueAt: new Date("2026-10-01T00:00:00Z") },
      { status: "ACCEPTED_RISK", dueAt: null },
    ], now);
    expect(p.total).toBe(4);
    expect(p.verified).toBe(1);
    expect(p.overdue).toBe(1);
    expect(p.exceptions).toBe(1);
  });

  it("scope matching ANDs its keys (§152)", () => {
    expect(findingMatchesCampaignScope({ cve: "CVE-2026-0001" }, { cve: "CVE-2026-0001" })).toBe(true);
    expect(findingMatchesCampaignScope({ cve: "CVE-2026-0001", kevOnly: true }, { cve: "CVE-2026-0001", kevListed: false })).toBe(false);
  });
});

describe("analytics (§110/§111)", () => {
  it("computes the three distinct MTTR clocks from history", () => {
    const t0 = new Date("2026-10-01T00:00:00Z");
    const h = (hours: number) => new Date(t0.getTime() + hours * 3600 * 1000);
    const metrics = computeRemediationMetrics({
      cases: [{
        caseId: "c1", createdAt: t0, dueAt: h(100), slaBreached: false, regressionCount: 1,
        entered: { ASSIGNED: h(2), FIX_CLAIMED: h(10), VERIFIED_FIXED: h(20), CLOSED: h(30) },
      }],
      verificationOutcomes: ["PASSED", "FAILED"],
      exceptionCaseIds: [],
    });
    expect(metrics.meanTimeToAssignHours).toBe(2);
    expect(metrics.meanTimeToClaimFixHours).toBe(10);
    expect(metrics.meanTimeToVerifyFixHours).toBe(10);
    expect(metrics.meanTimeToCloseHours).toBe(30);
    expect(metrics.verificationFailureRate).toBe(0.5);
    expect(metrics.regressionRate).toBe(1);
    expect(metrics.slaCompliancePct).toBe(100);
  });

  it("empty data yields nulls — never fabricated zeroes", () => {
    const metrics = computeRemediationMetrics({ cases: [], verificationOutcomes: [], exceptionCaseIds: [] });
    expect(metrics.meanTimeToCloseHours).toBeNull();
    expect(metrics.slaCompliancePct).toBeNull();
    expect(fixDurabilityHours([])).toBeNull();
  });
});

describe("NL remediation search (§117)", () => {
  it("translates the documented question shapes deterministically", () => {
    expect(translateRemediationQuery("Show overdue KEV findings.")).toEqual({ kind: "OVERDUE_KEV" });
    expect(translateRemediationQuery("Which fixes are waiting for verification?")).toEqual({ kind: "WAITING_VERIFICATION" });
    expect(translateRemediationQuery("Show regressions from the last 30 days.")).toEqual({ kind: "REGRESSIONS_SINCE", days: 30 });
    expect(translateRemediationQuery("delete everything")).toBeNull();
  });
});
