import { describe, expect, it } from "vitest";
import { classifyAutomationName, classifyProfile, isSchedulableProfile } from "./safety";
import { expressionForFrequency, minCronIntervalMinutes, nextCronRun, parseCron, validateCronExpression } from "./cron";
import { evaluateFrequency } from "./frequency";
import { evaluateWindows } from "./windows";
import {
  checkConcurrency, decideMissedRuns, decideRetry, findEquivalentRunningScan, planTick, scheduleRunKey,
} from "./runs";
import { decideLease, isLeaseStale } from "./lease";
import { buildAssetSnapshotEntry, buildFindingSnapshotEntry, rollupPostureSnapshots } from "./snapshots";
import { diffAssetSnapshots, diffFindingSnapshots, diffIntelSnapshots } from "./diff";
import { checkLoopGuard, matchesWorkflow, validateWorkflowDsl, workflowDedupKey } from "./workflow";
import { alertFingerprint, alertGroupKey, checkThrottle, isQuietHours, policyAdmitsEvent } from "./notifications";
import { validateWebhookDestination } from "./webhook";
import { evaluateAutoRetestEligibility } from "./retest-policy";

const T0 = new Date("2026-10-08T00:00:00Z"); // Thursday

describe("safe automation classification (§9–§11, §103–§106)", () => {
  it("allows static/safe profiles (§103/§104/§105)", () => {
    for (const p of ["BINARY_COMPREHENSIVE_STATIC", "MOBILE_STATIC_BASELINE", "WIRELESS_PASSIVE_BASELINE", "PASSIVE_RECON", "AD_BASELINE", "KUBERNETES_BASELINE"]) {
      expect(isSchedulableProfile(p), p).toBe(true);
      expect(classifyProfile(p).safetyClass).toBe("SAFE_AUTOMATED");
    }
  });
  it("blocks approval-gated and runtime profiles from unattended automation", () => {
    expect(classifyProfile("BINARY_CONTROLLED_DEBUG").safetyClass).toBe("PROHIBITED_AUTOMATION");
    expect(classifyProfile("MOBILE_DYNAMIC_CONTROLLED").safetyClass).toBe("PROHIBITED_AUTOMATION");
    expect(classifyProfile("NETWORK_INTERNAL").safetyClass).toBe("APPROVAL_REQUIRED");
    expect(classifyProfile("WEB_COMPREHENSIVE").schedulable).toBe(false);
    expect(classifyProfile("SOMETHING_UNKNOWN").schedulable).toBe(false); // fail closed
  });
  it("classifies §11 technique names as prohibited (identity test §106)", () => {
    for (const name of ["password spraying", "Kerberoasting", "ntlm-relay", "Wifite active run", "evil twin AP", "credential dumping"]) {
      expect(classifyAutomationName(name), name).toBe("PROHIBITED_AUTOMATION");
    }
    expect(classifyAutomationName("LDAP posture scan")).not.toBe("PROHIBITED_AUTOMATION");
    expect(classifyAutomationName("PingCastle posture")).not.toBe("PROHIBITED_AUTOMATION");
  });
});

describe("cron engine (§12/§14)", () => {
  it("validates the governed grammar and rejects the rest", () => {
    expect(validateCronExpression("0 2 * * *")).toEqual([]);
    expect(validateCronExpression("*/15 * * * *")).toEqual([]);
    expect(validateCronExpression("0 2 * *")).toHaveLength(1);
    expect(validateCronExpression("99 * * * *")).toHaveLength(1);
    expect(validateCronExpression("@daily")).toHaveLength(1);
    expect(() => parseCron("0 2 * * MON")).toThrow();
  });
  it("computes next runs in the schedule's own timezone", () => {
    // 02:00 Asia/Kolkata = 20:30 UTC previous day.
    const next = nextCronRun("0 2 * * *", "Asia/Kolkata", new Date("2026-10-08T00:00:00Z"));
    expect(next?.toISOString()).toBe("2026-10-08T20:30:00.000Z");
    const utc = nextCronRun("0 2 * * *", "UTC", new Date("2026-10-08T00:00:00Z"));
    expect(utc?.toISOString()).toBe("2026-10-08T02:00:00.000Z");
  });
  it("measures minimum intervals", () => {
    expect(minCronIntervalMinutes("* * * * *", "UTC")).toBe(1);
    expect(minCronIntervalMinutes("0 * * * *", "UTC")).toBe(60);
    expect(minCronIntervalMinutes("0 2 * * *", "UTC")).toBe(1440);
    expect(expressionForFrequency("DAILY")).toBe("0 2 * * *");
  });
});

describe("frequency guardrail (§13)", () => {
  it("refuses an every-minute comprehensive schedule", () => {
    const ev = evaluateFrequency({ profile: "SOURCE_COMPREHENSIVE", expression: "* * * * *", timezone: "UTC", targetCount: 1, runsTodayForWorkspace: 0, dailyRunBudget: 200 });
    expect(ev.allowed).toBe(false);
    expect(ev.reasonCode).toBe("INTERVAL_TOO_SHORT");
  });
  it("refuses non-schedulable profiles and exhausted budgets", () => {
    expect(evaluateFrequency({ profile: "BINARY_CONTROLLED_DEBUG", expression: "0 2 * * *", timezone: "UTC", targetCount: 1, runsTodayForWorkspace: 0, dailyRunBudget: 200 }).reasonCode).toBe("PROFILE_NOT_SCHEDULABLE");
    expect(evaluateFrequency({ profile: "PASSIVE_RECON", expression: "0 * * * *", timezone: "UTC", targetCount: 1, runsTodayForWorkspace: 200, dailyRunBudget: 200 }).reasonCode).toBe("DAILY_BUDGET_EXHAUSTED");
  });
  it("allows a daily light schedule", () => {
    expect(evaluateFrequency({ profile: "PASSIVE_RECON", expression: "0 2 * * *", timezone: "UTC", targetCount: 3, runsTodayForWorkspace: 0, dailyRunBudget: 200 }).allowed).toBe(true);
  });
});

describe("windows (§15/§16/§101)", () => {
  it("blackout defers to the blackout end", () => {
    const ev = evaluateWindows(new Date("2026-10-08T10:00:00Z"), [], [
      { startsAt: "2026-10-08T09:00:00Z", endsAt: "2026-10-08T12:00:00Z", reason: "production release" },
    ]);
    expect(ev.allowed).toBe(false);
    expect(ev.reasonCode).toBe("BLACKOUT");
    expect(ev.deferredUntil?.toISOString()).toBe("2026-10-08T12:00:00.000Z");
  });
  it("maintenance allowed-hours gate by local time + day", () => {
    const win = [{ daysOfWeek: [4], startTime: "09:00", endTime: "17:00", timezone: "UTC", mode: "ALLOWED_HOURS" as const }];
    expect(evaluateWindows(new Date("2026-10-08T10:00:00Z"), win, []).allowed).toBe(true); // Thu 10:00
    expect(evaluateWindows(new Date("2026-10-08T20:00:00Z"), win, []).reasonCode).toBe("OUTSIDE_MAINTENANCE");
    expect(evaluateWindows(new Date("2026-10-09T10:00:00Z"), win, []).allowed).toBe(false); // Friday
  });
});

describe("runs: idempotency, missed, retry, dedupe (§18–§21)", () => {
  it("run keys are deterministic per schedule + due instant", () => {
    const a = scheduleRunKey({ scheduleId: "s1", scheduledFor: T0 });
    expect(a).toBe(scheduleRunKey({ scheduleId: "s1", scheduledFor: "2026-10-08T00:00:00.000Z" }));
    expect(a).not.toBe(scheduleRunKey({ scheduleId: "s1", scheduledFor: new Date("2026-10-09T00:00:00Z") }));
  });
  it("missed-run policies never create an unlimited backlog", () => {
    const missed = [0, 1, 2, 3, 4, 5].map((h) => new Date(T0.getTime() + h * 3600_000));
    expect(decideMissedRuns("SKIP", missed).runsToCreate).toBe(0);
    expect(decideMissedRuns("RUN_ONCE", missed).runsToCreate).toBe(1);
    const catchUp = decideMissedRuns("CATCH_UP_LIMITED", missed);
    expect(catchUp.runsToCreate).toBe(3);
    expect(catchUp.skippedInstants).toHaveLength(3);
  });
  it("policy denials are never retried; transient errors back off; exhaustion dead-letters", () => {
    expect(decideRetry({ attempts: 0, maxAttempts: 3, errorClass: "POLICY_DENIED", now: T0 }).retry).toBe(false);
    expect(decideRetry({ attempts: 0, maxAttempts: 3, errorClass: "AUTHORIZATION_EXPIRED", now: T0 }).retry).toBe(false);
    const r = decideRetry({ attempts: 1, maxAttempts: 3, errorClass: "QUEUE_UNAVAILABLE", now: T0 });
    expect(r.retry).toBe(true);
    expect(r.nextAttemptAt?.getTime()).toBe(T0.getTime() + 120_000);
    expect(decideRetry({ attempts: 3, maxAttempts: 3, errorClass: "TRANSIENT", now: T0 }).retry).toBe(false);
  });
  it("duplicate prevention: equivalent running scan blocks (§102)", () => {
    const running = [{ scanId: "x", assessmentId: "a1", profile: "WEB_BASELINE", status: "RUNNING" }];
    expect(findEquivalentRunningScan(running, { assessmentId: "a1", profile: "WEB_BASELINE" })?.scanId).toBe("x");
    expect(findEquivalentRunningScan(running, { assessmentId: "a1", profile: "PASSIVE_RECON" })).toBeUndefined();
    expect(checkConcurrency({ runningForWorkspace: 2, runningForTarget: 0, maxConcurrentForWorkspace: 2 }).allowed).toBe(false);
  });
});

describe("tick planning: backpressure + fairness (§95/§96/§117/§118)", () => {
  const due = [
    { scheduleId: "a1", workspaceId: "A", nextRunAt: T0 },
    { scheduleId: "a2", workspaceId: "A", nextRunAt: T0 },
    { scheduleId: "a3", workspaceId: "A", nextRunAt: T0 },
    { scheduleId: "b1", workspaceId: "B", nextRunAt: T0 },
  ];
  it("overloaded queue defers everything instead of flooding", () => {
    const plan = planTick({ due, queueDepth: 500, queueDepthThreshold: 100, runningByWorkspace: {}, maxConcurrentByWorkspace: { A: 5, B: 5 } });
    expect(plan.selected).toHaveLength(0);
    expect(plan.deferred).toHaveLength(4);
  });
  it("round-robins across workspaces so B is not starved by A", () => {
    const plan = planTick({ due, queueDepth: 0, queueDepthThreshold: 100, runningByWorkspace: {}, maxConcurrentByWorkspace: { A: 2, B: 2 }, maxSelections: 3 });
    expect(plan.selected.map((s) => s.scheduleId)).toEqual(["a1", "b1", "a2"]);
  });
});

describe("lease (§23/§24/§98/§119)", () => {
  it("one holder only; expired lease is taken over safely", () => {
    const existing = { owner: "node-1", leaseUntil: new Date(T0.getTime() + 60_000), heartbeatAt: T0 };
    expect(decideLease({ existing, owner: "node-2", now: T0, ttlSeconds: 120 }).action).toBe("HELD_BY_OTHER");
    const later = new Date(T0.getTime() + 61_000);
    expect(decideLease({ existing, owner: "node-2", now: later, ttlSeconds: 120 }).action).toBe("ACQUIRE");
    expect(decideLease({ existing, owner: "node-1", now: T0, ttlSeconds: 120 }).action).toBe("RENEW");
    expect(isLeaseStale(existing, new Date(T0.getTime() + 121_000), 120)).toBe(true);
  });
});

describe("snapshots + drift (§29–§48, §107–§110)", () => {
  const asset = (over: Partial<Parameters<typeof buildAssetSnapshotEntry>[0]>) => buildAssetSnapshotEntry({
    assetKey: "t1|HOST|example.com", host: "example.com", type: "HOST", exposure: "INTERNET_FACING",
    scopeStatus: "IN_SCOPE", criticality: "HIGH", ports: [80, 443], services: ["https"], endpointCount: 3, ...over,
  });
  it("asset diff: NEW_PORT on 8443 (§107)", () => {
    const { assetDrift, surfaceChanges } = diffAssetSnapshots({ previous: [asset({})], current: [asset({ ports: [80, 443, 8443] })] });
    expect(assetDrift[0]?.type).toBe("CHANGED");
    expect(surfaceChanges.some((c) => c.type === "NEW_PORT" && c.detail.includes("8443"))).toBe(true);
  });
  it("exposure drift PRIVATE → INTERNET_FACING is high priority (§108)", () => {
    const { surfaceChanges } = diffAssetSnapshots({ previous: [asset({ exposure: "PRIVATE" })], current: [asset({ exposure: "INTERNET_FACING" })] });
    expect(surfaceChanges.some((c) => c.type === "NEW_PUBLIC_RESOURCE" && c.priority === "HIGH")).toBe(true);
  });
  it("new assets are DISCOVERED, never auto-authorized (§35)", () => {
    const { surfaceChanges } = diffAssetSnapshots({ previous: [], current: [asset({})] });
    expect(surfaceChanges[0]?.detail).toContain("not authorized for intrusive testing");
  });
  const finding = (over: Partial<Parameters<typeof buildFindingSnapshotEntry>[0]>) => buildFindingSnapshotEntry({
    fingerprint: "fp1", status: "OPEN", lifecycleStatus: "IN_PROGRESS", severity: "HIGH", priority: "P1",
    riskScore: 70, verificationStatus: "UNVERIFIED", kevListed: false, ...over,
  });
  it("finding drift: RESOLVED → observed again = REOPENED (§109)", () => {
    const events = diffFindingSnapshots({ previous: [finding({ lifecycleStatus: "RESOLVED", status: "RESOLVED" })], current: [finding({})] });
    expect(events.some((e) => e.type === "REOPENED")).toBe(true);
  });
  it("KEV drift: newly listed CVE raises KEV_ADDED per affected finding (§110)", () => {
    const events = diffIntelSnapshots({
      previous: [{ cve: "CVE-2026-0001", kevListed: false, epssScore: 0.2 }],
      current: [{ cve: "CVE-2026-0001", kevListed: true, epssScore: 0.5 }],
      findingsByCve: new Map([["CVE-2026-0001", ["f1"]]]),
    });
    expect(events.some((e) => e.type === "KEV_ADDED" && e.findingId === "f1")).toBe(true);
    expect(events.some((e) => e.type === "EPSS_INCREASED")).toBe(true);
  });
  it("rollups bucket by day taking the last snapshot (§92)", () => {
    const snaps = [
      { capturedAt: new Date("2026-10-08T01:00:00Z"), riskScore: 10 },
      { capturedAt: new Date("2026-10-08T05:00:00Z"), riskScore: 20 },
      { capturedAt: new Date("2026-10-09T01:00:00Z"), riskScore: 30 },
    ];
    const rolled = rollupPostureSnapshots(snaps, "DAILY");
    expect(rolled).toHaveLength(2);
    expect(rolled[0]?.snapshot.riskScore).toBe(20);
  });
});

describe("workflow DSL + loop protection (§61–§64, §113/§114)", () => {
  it("validates typed workflows and executes all typed actions' matching (§113)", () => {
    const dsl = {
      trigger: "FINDING_VERIFIED",
      conditions: [
        { field: "severity", operator: "eq", value: "CRITICAL" },
        { field: "environment", operator: "eq", value: "PRODUCTION" },
      ],
      actions: [
        { type: "ASSIGN_FINDING", params: { team: "security" } },
        { type: "CREATE_NOTIFICATION", params: { channel: "IN_APP" } },
        { type: "SET_PRIORITY", params: { priority: "P0" } },
      ],
    };
    const v = validateWorkflowDsl(dsl);
    expect(v.ok).toBe(true);
    expect(matchesWorkflow({ trigger: "FINDING_VERIFIED", severity: "CRITICAL", environment: "PRODUCTION" }, v.value!)).toBe(true);
    expect(matchesWorkflow({ trigger: "FINDING_VERIFIED", severity: "HIGH", environment: "PRODUCTION" }, v.value!)).toBe(false);
  });
  it("rejects arbitrary code in workflow definitions (§61)", () => {
    const bad = validateWorkflowDsl({ trigger: "FINDING_CREATED", conditions: [], actions: [{ type: "CREATE_NOTIFICATION", params: { script: "rm -rf /" } }] });
    expect(bad.ok).toBe(false);
    expect(bad.errors.join(" ")).toContain("arbitrary code");
    expect(validateWorkflowDsl({ trigger: "FINDING_CREATED", conditions: [], actions: [{ type: "RUN_SHELL", params: {} }] }).ok).toBe(false);
  });
  it("loop guard stops recursive self-triggering (§114)", () => {
    const key = workflowDedupKey("w1", "e1", "CREATE_NOTIFICATION");
    expect(checkLoopGuard({ lineage: ["w1"], depth: 1, workflowId: "w1", executedKeys: new Set(), eventId: "e1", actionType: "CREATE_NOTIFICATION" }).allowed).toBe(false);
    expect(checkLoopGuard({ lineage: [], depth: 3, workflowId: "w1", executedKeys: new Set(), eventId: "e1", actionType: "CREATE_NOTIFICATION" }).allowed).toBe(false);
    expect(checkLoopGuard({ lineage: [], depth: 0, workflowId: "w1", executedKeys: new Set([key]), eventId: "e1", actionType: "CREATE_NOTIFICATION" }).allowed).toBe(false);
    expect(checkLoopGuard({ lineage: [], depth: 0, workflowId: "w1", executedKeys: new Set(), eventId: "e1", actionType: "CREATE_NOTIFICATION" }).allowed).toBe(true);
  });
});

describe("notifications: dedup, grouping, throttle, quiet hours (§67–§72, §116)", () => {
  const event = { type: "FINDING_CREATED", workspaceId: "ws1", findingId: "f1", severity: "HIGH", contentHash: "abc" };
  it("identical alert fingerprints dedupe; changed content does not", () => {
    expect(alertFingerprint(event)).toBe(alertFingerprint({ ...event }));
    expect(alertFingerprint(event)).not.toBe(alertFingerprint({ ...event, contentHash: "different" }));
    expect(alertGroupKey({ ...event, cve: "CVE-1" })).toBe("cve:CVE-1");
  });
  it("policy admission + throttle + quiet hours with emergency bypass", () => {
    const policy = {
      eventTypes: ["FINDING_CREATED"], channels: ["IN_APP" as const], dedupWindowMinutes: 60,
      quietHours: { startTime: "22:00", endTime: "07:00", timezone: "UTC" }, emergencySeverities: ["CRITICAL"], throttlePerHour: 2,
    };
    expect(policyAdmitsEvent(policy, event).admitted).toBe(true);
    expect(policyAdmitsEvent(policy, { ...event, type: "OTHER" }).admitted).toBe(false);
    expect(isQuietHours(policy, event, new Date("2026-10-08T23:00:00Z"))).toBe(true);
    expect(isQuietHours(policy, { ...event, severity: "CRITICAL" }, new Date("2026-10-08T23:00:00Z"))).toBe(false);
    expect(checkThrottle({ priorTimestamps: [new Date(), new Date()], now: new Date(), limitPerHour: 2 }).allowed).toBe(false);
  });
});

describe("webhook SSRF protection (§73/§74/§115)", () => {
  const resolver = async (host: string) => (host === "hooks.example.com" ? ["93.184.216.34"] : ["10.0.0.5"]);
  it("blocks loopback, metadata and private destinations", async () => {
    for (const url of ["https://127.0.0.1/hook", "https://169.254.169.254/latest/meta-data", "https://localhost/hook", "https://internal.example.com/hook"]) {
      const r = await validateWebhookDestination({ url, allowlist: [], resolver });
      expect(r.ok, url).toBe(false);
    }
  });
  it("requires HTTPS and allowlist membership; public allowlisted host passes", async () => {
    expect((await validateWebhookDestination({ url: "http://hooks.example.com/x", allowlist: [], resolver })).ok).toBe(false);
    expect((await validateWebhookDestination({ url: "https://hooks.example.com/x", allowlist: ["other.example.com"], resolver })).ok).toBe(false);
    expect((await validateWebhookDestination({ url: "https://hooks.example.com/x", allowlist: ["hooks.example.com"], resolver })).ok).toBe(true);
  });
});

describe("auto-retest eligibility (§51–§55, §111/§112)", () => {
  it("safe TLS finding marked remediated is eligible via RetestRouter + SAFE validator", () => {
    const ev = evaluateAutoRetestEligibility({
      id: "f1", title: "TLS 1.0 enabled", vulnClass: "TLS", host: "example.com", port: 443,
      lifecycleStatus: "REMEDIATED", sourceDomain: "WEB", sources: ["testssl"],
    }, "REMEDIATION_MARKER");
    expect(ev.eligible).toBe(true);
    expect(ev.validatorSlug).toBe("tls-recheck");
    expect(ev.route?.kind).toBe("WEB_VALIDATOR");
  });
  it("intrusive/exploitation findings can never auto-retest (§112)", () => {
    const ev = evaluateAutoRetestEligibility({
      id: "f2", title: "RCE exploitation required to validate", vulnClass: "RCE EXPLOITATION", host: "example.com",
      lifecycleStatus: "REMEDIATED", sourceDomain: "WEB", sources: ["nuclei"],
    }, "SCHEDULED");
    expect(ev.eligible).toBe(false);
  });
  it("findings with no safe route or validator are ineligible", () => {
    const ev = evaluateAutoRetestEligibility({
      id: "f3", title: "Something exotic", vulnClass: "EXOTIC", lifecycleStatus: "REMEDIATED",
      sourceDomain: "MANUAL", sources: [],
    }, "SCHEDULED");
    expect(ev.eligible).toBe(false);
  });
});
