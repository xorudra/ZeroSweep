import { describe, expect, it } from "vitest";
import { normalizeCveId, normalizeCweId, parseCpe, formatCpe, normalizeCvss, extractCveIds } from "./normalize";
import {
  InMemoryIntelligenceDataset, IntelligenceSyncEngine, VulnerabilityIntelligenceServiceV2,
  NvdIntelligenceProvider, EpssIntelligenceProvider, KevIntelligenceProvider, resolveCvssTrust,
} from "./intelligence";
import { enrichFinding, CpeCveCorrelationService } from "./enrichment";
import { computeRiskV2 } from "./risk-v2";
import { evaluateLifecycleTransition, canTransition, isRiskAcceptanceExpired, sanitizeCommentText } from "./lifecycle";
import { DEFAULT_SLA_POLICY, computeDueAt, slaStatus } from "./sla";
import { groupFindingsForRemediation } from "./grouping";
import { planRetest, judgeRetest } from "./retest";
import { EPSS_FIXTURE, FIXTURE_CVE, KEV_FIXTURE, NVD_FIXTURE } from "./fixtures";

/**
 * Prompt 11 intelligence/lifecycle tests (§93–§99): all data comes from
 * recorded fixtures. The shipped dataset is empty; enrichment finds data
 * ONLY after a fixture sync puts it there.
 */

async function syncedDataset(): Promise<InMemoryIntelligenceDataset> {
  const ds = new InMemoryIntelligenceDataset();
  const payloads: Record<string, string> = { NVD: NVD_FIXTURE, FIRST_EPSS: EPSS_FIXTURE, CISA_KEV: KEV_FIXTURE };
  const engine = new IntelligenceSyncEngine(ds, async (s) => payloads[s]!, { sleep: async () => {}, now: () => new Date("2026-10-07T00:00:00Z") });
  await engine.sync(new NvdIntelligenceProvider());
  await engine.sync(new EpssIntelligenceProvider());
  await engine.sync(new KevIntelligenceProvider());
  return ds;
}

describe("identifier normalization (§23–§26)", () => {
  it("canonicalizes CVE/CWE and rejects garbage instead of repairing it", () => {
    expect(normalizeCveId("cve-2021-44228")).toBe("CVE-2021-44228");
    expect(normalizeCveId("CVE-2021-44228")).toBe("CVE-2021-44228");
    expect(normalizeCveId("not-a-cve")).toBeUndefined();
    expect(normalizeCveId("CVE-1800-0001")).toBeUndefined();
    expect(normalizeCweId(502)).toBe("CWE-502");
    expect(normalizeCweId("cwe-79")).toBe("CWE-79");
    expect(normalizeCweId("CWE-")).toBeUndefined();
    expect(extractCveIds("see CVE-2021-44228 and cve-2020-0001")).toEqual(["CVE-2021-44228", "CVE-2020-0001"]);
  });

  it("parses CPE 2.3 and legacy 2.2, formats canonically, rejects malformed", () => {
    const legacy = parseCpe("cpe:/a:apache:log4j:2.14.1");
    expect(legacy).toMatchObject({ part: "a", vendor: "apache", product: "log4j", version: "2.14.1" });
    expect(formatCpe(legacy!)).toBe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
    expect(parseCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")?.product).toBe("log4j");
    expect(parseCpe("cpe:2.3:a:apache")).toBeUndefined();
    expect(parseCpe("not a cpe")).toBeUndefined();
  });

  it("keeps CVSS versions distinct and rejects out-of-range scores (§26)", () => {
    expect(normalizeCvss({ score: 10, vector: "CVSS:3.1/AV:N", source: "NVD" })?.version).toBe("3.1");
    expect(normalizeCvss({ score: 7.5, vector: "AV:N/AC:L", source: "NESSUS" })?.version).toBe("2.0");
    expect(normalizeCvss({ score: 11, source: "X" })).toBeUndefined();
  });
});

describe("intelligence sync (§29–§30)", () => {
  it("starts NEVER_SYNCED with an empty dataset — nothing to enrich", () => {
    const ds = new InMemoryIntelligenceDataset();
    expect(ds.syncState("NVD").status).toBe("NEVER_SYNCED");
    expect(new VulnerabilityIntelligenceServiceV2(ds).cve(FIXTURE_CVE)).toBeUndefined();
  });

  it("syncs fixture payloads incrementally: second identical sync is UNCHANGED", async () => {
    const ds = new InMemoryIntelligenceDataset();
    const engine = new IntelligenceSyncEngine(ds, async () => NVD_FIXTURE, { sleep: async () => {} });
    const first = await engine.sync(new NvdIntelligenceProvider());
    expect(first.status).toBe("SYNCED");
    expect(ds.getCve(FIXTURE_CVE)?.cvss?.baseScore).toBe(10);
    expect(ds.getCve(FIXTURE_CVE)?.cweIds).toEqual(["CWE-502"]);
    const second = await engine.sync(new NvdIntelligenceProvider());
    expect(second.status).toBe("UNCHANGED");
    expect(ds.syncState("NVD").lastSuccessAt).toBeTruthy();
  });

  it("retries with backoff and records FAILED without losing prior state", async () => {
    const ds = new InMemoryIntelligenceDataset();
    let calls = 0;
    const engine = new IntelligenceSyncEngine(ds, async () => { calls++; throw new Error("egress down"); }, { sleep: async () => {}, maxAttempts: 3 });
    const outcome = await engine.sync(new NvdIntelligenceProvider());
    expect(outcome.status).toBe("FAILED");
    expect(calls).toBe(3);
    expect(ds.syncState("NVD").status).toBe("FAILED");
  });
});

describe("enrichment (§35/§36) + source trust (§32)", () => {
  it("attaches CVE/EPSS/KEV only when the local dataset actually holds them", async () => {
    const ds = await syncedDataset();
    const enr = enrichFinding({ cve: FIXTURE_CVE, cvssScore: 9.8 }, ds);
    expect(enr.cveId).toBe(FIXTURE_CVE);
    expect(enr.epss?.score).toBeCloseTo(0.94358);
    expect(enr.epss?.percentile).toBeCloseTo(0.99913); // §98: score ≠ percentile
    expect(enr.kevListed).toBe(true);
    // §32: scanner CVSS 9.8 kept as effective; intelligence 10.0 preserved.
    expect(enr.cvss.effectiveScore).toBe(9.8);
    expect(enr.cvss.intelligenceScore).toBe(10);
    expect(enr.cvss.reason).toContain("preserved separately");
  });

  it("empty dataset → enrichment attaches nothing and says so", () => {
    const enr = enrichFinding({ cve: FIXTURE_CVE }, new InMemoryIntelligenceDataset());
    expect(enr.epss).toBeUndefined();
    expect(enr.kevListed).toBe(false);
    expect(enr.cvss.effectiveScore).toBeUndefined();
    expect(enr.notes.join(" ")).toContain("no local intelligence record");
  });

  it("is idempotent: repeated enrichment yields identical link keys (§36)", async () => {
    const ds = await syncedDataset();
    const a = enrichFinding({ cve: FIXTURE_CVE, cwe: "502", cpe: "cpe:/a:apache:log4j:2.14.1" }, ds);
    const b = enrichFinding({ cve: FIXTURE_CVE, cwe: "502", cpe: "cpe:/a:apache:log4j:2.14.1" }, ds);
    expect(a.linkKeys).toEqual(b.linkKeys);
    expect(new Set(a.linkKeys).size).toBe(a.linkKeys.length);
  });

  it("resolveCvssTrust preserves both scores (§32)", () => {
    expect(resolveCvssTrust({}).effectiveScore).toBeUndefined();
    expect(resolveCvssTrust({ intelligenceScore: 7.5 }).effectiveScore).toBe(7.5);
    expect(resolveCvssTrust({ scannerScore: 5, intelligenceScore: 5 }).reason).toContain("agree");
  });
});

describe("CPE correlation (§33/§34/§96)", () => {
  it("a CPE match with no detection is POTENTIAL_EXPOSURE, never a confirmed vulnerability", async () => {
    const ds = await syncedDataset();
    ds.upsertCpe({
      canonical: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", part: "a", vendor: "apache",
      product: "log4j", version: "2.14.1", cveIds: [FIXTURE_CVE], source: "FIXTURE",
    });
    const svc = new CpeCveCorrelationService(ds);
    const out = svc.correlate({ cpe: "cpe:/a:apache:log4j:2.14.1" });
    expect(out).toHaveLength(1);
    expect(out[0]!.detectionKind).toBe("POTENTIAL_EXPOSURE");
    expect(svc.correlate({ cpe: "cpe:/a:nginx:nginx:1.25.3" })).toEqual([]);
  });
});

describe("Risk Engine V2 (§37–§40, §97)", () => {
  it("KEV escalates priority a full band without changing severity semantics", async () => {
    const ds = await syncedDataset();
    const enr = enrichFinding({ cve: FIXTURE_CVE }, ds);
    const withKev = computeRiskV2({ severity: "HIGH", confidence: 0.8, enrichment: enr });
    const without = computeRiskV2({ severity: "HIGH", confidence: 0.8 });
    expect(withKev.factors.join(" ")).toContain("KEV");
    expect(withKev.score).toBeGreaterThan(without.score);
    expect(withKev.calcVersion).toBeTruthy();
    expect(withKev.intelSnapshot).toBe(ds.snapshotId());
  });

  it("an exploit reference is a signal, never a CONFIRMED marking (§21)", () => {
    const r = computeRiskV2({ severity: "MEDIUM", confidence: 0.5, exploitReferenceExists: true });
    expect(r.factors.join(" ")).toContain("NOT confirmed exploitable");
  });
});

describe("lifecycle state machine (§47–§51)", () => {
  it("rejects FALSE_POSITIVE → IN_PROGRESS directly (§48)", () => {
    expect(canTransition("FALSE_POSITIVE", "IN_PROGRESS")).toBe(false);
    expect(evaluateLifecycleTransition({ from: "FALSE_POSITIVE", to: "IN_PROGRESS", actorId: "u1" }).ok).toBe(false);
    expect(canTransition("FALSE_POSITIVE", "NEW")).toBe(true);
  });

  it("risk acceptance requires reason, approver and a future expiry (§49)", () => {
    const base = { from: "TRIAGED" as const, to: "ACCEPTED_RISK" as const, actorId: "u1" };
    expect(evaluateLifecycleTransition({ ...base }).ok).toBe(false);
    expect(evaluateLifecycleTransition({ ...base, reason: "compensating control", riskAcceptance: { approverId: "admin", expiresAt: new Date(Date.now() - 1000) } }).ok).toBe(false);
    const ok = evaluateLifecycleTransition({ ...base, reason: "compensating control", riskAcceptance: { approverId: "admin", expiresAt: new Date(Date.now() + 86400_000) } });
    expect(ok.ok).toBe(true);
    expect(ok.effects.riskAcceptance?.acceptedBy).toBe("admin");
  });

  it("false positive requires reason + reviewer; evidence is preserved by design (§51)", () => {
    expect(evaluateLifecycleTransition({ from: "TRIAGED", to: "FALSE_POSITIVE", actorId: "u1", reason: "banner only" }).ok).toBe(false);
    expect(evaluateLifecycleTransition({ from: "TRIAGED", to: "FALSE_POSITIVE", actorId: "u1", reason: "banner only", reviewerId: "u1" }).ok).toBe(true);
  });

  it("expired acceptance is detectable for the return-to-review flow (§50)", () => {
    expect(isRiskAcceptanceExpired({ lifecycleStatus: "ACCEPTED_RISK", riskAcceptanceExpiresAt: new Date(Date.now() - 1) })).toBe(true);
    expect(isRiskAcceptanceExpired({ lifecycleStatus: "ACCEPTED_RISK", riskAcceptanceExpiresAt: new Date(Date.now() + 10000) })).toBe(false);
  });

  it("sanitizes comment text (§45)", () => {
    expect(sanitizeCommentText("<script>alert(1)</script>hello")).toBe("alert(1)hello");
  });
});

describe("SLA (§41–§43)", () => {
  it("computes dueAt from the policy window and tracks status", () => {
    const created = new Date("2026-10-01T00:00:00Z");
    const due = computeDueAt(DEFAULT_SLA_POLICY, { priority: "P1", severity: "HIGH", createdAt: created });
    expect(due?.toISOString()).toBe("2026-10-03T00:00:00.000Z"); // P1 = 48h
    expect(slaStatus({ dueAt: due, lifecycleStatus: "CONFIRMED", createdAt: created, severity: "HIGH" }, new Date("2026-10-02T00:00:00Z"))).toBe("ON_TRACK");
    expect(slaStatus({ dueAt: due, lifecycleStatus: "CONFIRMED", createdAt: created, severity: "HIGH" }, new Date("2026-10-04T00:00:00Z"))).toBe("OVERDUE");
    expect(slaStatus({ dueAt: due, lifecycleStatus: "RESOLVED", createdAt: created, severity: "HIGH" }, new Date("2026-10-04T00:00:00Z"))).toBe("EXEMPT");
    expect(slaStatus({ dueAt: due, lifecycleStatus: "ACCEPTED_RISK", createdAt: created, severity: "HIGH" }, new Date("2026-10-04T00:00:00Z"))).toBe("EXEMPT");
  });
});

describe("remediation grouping (§53/§54)", () => {
  it("groups deterministically by CVE then configuration class", () => {
    const groups = groupFindingsForRemediation([
      { id: "1", cve: FIXTURE_CVE, host: "a", title: "x", lifecycleStatus: "CONFIRMED", priority: "P0", severity: "CRITICAL" },
      { id: "2", cve: FIXTURE_CVE, host: "b", title: "x", lifecycleStatus: "CONFIRMED", priority: "P0", severity: "CRITICAL" },
      { id: "3", vulnClass: "TLS_WEAK_PROTOCOL", host: "a", title: "tls", lifecycleStatus: "NEW", priority: "P2", severity: "MEDIUM" },
    ]);
    expect(groups[0]!.kind).toBe("CVE");
    expect(groups[0]!.findingIds.sort()).toEqual(["1", "2"]);
    expect(groups[1]!.kind).toBe("CONFIG_CLASS");
  });
});

describe("retest planning (§55–§58, §99)", () => {
  it("plans a targeted retest reusing the original tool; judges outcomes", () => {
    const res = planRetest({
      host: "192.0.2.10", port: 8080, vulnClass: "GENERIC_VULNERABILITY", cve: FIXTURE_CVE,
      sources: ["nessus-professional"], checkReference: "155275", lifecycleStatus: "REMEDIATED",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.plan.sourceTool).toBe("nessus-professional");
    expect(judgeRetest(res.plan, [])).toBe("RESOLVED");
    expect(judgeRetest(res.plan, [res.plan.canonicalFingerprint])).toBe("REOPENED");
  });

  it("refuses to retest a finding that was never remediated", () => {
    expect(planRetest({ sources: ["nuclei"], lifecycleStatus: "NEW" }).ok).toBe(false);
  });
});
