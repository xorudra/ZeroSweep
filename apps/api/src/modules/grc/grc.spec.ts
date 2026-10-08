import { FrameworkService } from "./frameworks/framework.service";
import { ControlService } from "./controls/control.service";
import { EvidenceService } from "./evidence/evidence.service";
import { MonitoringService } from "./monitoring/monitoring.service";
import { AssessmentService } from "./assessments/assessment.service";
import { RiskService } from "./risks/risk.service";
import { PolicyService } from "./policies/policy.service";
import { GrcAuditService } from "./audits/audit.service";
import { VendorService } from "./vendors/vendor.service";
import { FindingLinkService } from "./findings/finding-link.service";
import { GrcAnalyticsService } from "./analytics/analytics.service";
import { GrcReportService } from "./reports/report.service";
import { GrcBackupService } from "./reports/backup.service";
import { AiGrcService } from "./ai/ai-grc.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (same pattern as prior phase specs).          */
/* ------------------------------------------------------------------ */

function mockFn(impl: (...args: never[]) => Promise<unknown>) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => {
    calls.push(args);
    return impl(...(args as never[]));
  };
  return Object.assign(fn, { calls });
}
type Row = Record<string, unknown> & { id: string };

function cmp(a: unknown, b: unknown): number {
  const av = a instanceof Date ? a.getTime() : (a as number);
  const bv = b instanceof Date ? b.getTime() : (b as number);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    if ("not" in c) {
      if (c.not === null) { if (value === null || value === undefined) return false; }
      else if (value === c.not) return false;
      continue;
    }
    if ("gte" in c && cmp(value, c.gte) < 0) return false;
    if ("lte" in c && cmp(value, c.lte) > 0) return false;
    if ("gt" in c && cmp(value, c.gt) <= 0) return false;
    if ("lt" in c && cmp(value, c.lt) >= 0) return false;
    if (!("gte" in c) && !("lte" in c) && !("gt" in c) && !("lt" in c)) return false;
  }
  return true;
}

let seq = 0;
function makeTable(name: string) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      // Mirror @default(now()) columns the services read back.
      for (const f of ["collectedAt", "evaluatedAt", "observedAt", "assessedAt", "generatedAt", "validFrom"]) {
        if (row[f] === undefined) row[f] = stamp;
      }
      rows.push(row);
      return row;
    },
    async createMany({ data }: { data: Row[] }) {
      for (const d of data) await table.create({ data: d });
      return { count: data.length };
    },
    async findUnique({ where }: { where: Record<string, unknown> }) {
      return rows.find((r) => matches(r, where)) ?? null;
    },
    async findFirst(args: { where?: Record<string, unknown>; orderBy?: Record<string, string> } = {}) {
      const list = await table.findMany({ ...args, take: 1 });
      return list[0] ?? null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number; orderBy?: Record<string, string> | Array<Record<string, string>> } = {}) {
      let out = rows.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy[0] : args.orderBy;
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0]!;
        out = [...out].sort((a, b) => cmp(a[field], b[field]) * (dir === "desc" ? -1 : 1));
      }
      if (args.take) out = out.slice(0, args.take);
      return out;
    },
    async update({ where, data }: { where: Record<string, unknown>; data: Row }) {
      const row = rows.find((r) => matches(r, where));
      if (!row) throw new Error(`row not found in ${name}`);
      Object.assign(row, data);
      return row;
    },
    async updateMany({ where, data }: { where?: Record<string, unknown>; data: Row }) {
      let count = 0;
      for (const r of rows) if (matches(r, where)) { Object.assign(r, data); count++; }
      return { count };
    },
    async delete({ where }: { where: Record<string, unknown> }) {
      const i = rows.findIndex((r) => matches(r, where));
      if (i >= 0) rows.splice(i, 1);
      return {};
    },
    async count(args: { where?: Record<string, unknown> } = {}) {
      return rows.filter((r) => matches(r, args.where)).length;
    },
  };
  return table;
}

const TABLES = [
  "workspace", "auditLog", "notification", "complianceFramework", "complianceRequirement",
  "securityControl", "controlOwner", "controlTest", "controlFrameworkMapping", "controlSignal",
  "controlEvaluation", "complianceEvidence", "evidenceFreshnessPolicy", "complianceAssessment",
  "assessmentRequirementResult", "complianceDriftEvent", "controlTestSchedule", "riskRegister",
  "riskMatrix", "riskRecord", "riskLink", "riskTreatmentPlan", "riskTreatmentAction",
  "riskAcceptance", "riskReview", "governancePolicy", "policyAcknowledgement",
  "auditEngagement", "auditEvidenceRequest", "auditFinding", "auditEvidencePackage",
  "auditorAccessGrant", "findingControlLink", "thirdPartyVendor", "vendorRiskAssessment",
  "grcReportSnapshot", "grcRetentionPolicy", "riskException", "organizationSecurityPolicy",
  "passwordPolicy", "enterpriseSsoProvider", "accessReview", "webAuthnCredential",
  "securityPostureSnapshot", "finding", "scan", "softwareBillOfMaterials", "controlAssessment",
  "qualityGateResult", "repositorySecurityPolicy",
] as const;

function makeFake() {
  const db: Record<string, ReturnType<typeof makeTable>> = {};
  for (const t of TABLES) db[t] = makeTable(t);
  return db;
}

/* ------------------------------------------------------------------ */

const ADMIN: RequestUser = { id: "u-admin", email: "rudra@example.com", organizationId: "org-1", role: "OWNER" };
const ADMIN2: RequestUser = { id: "u-admin2", email: "second@example.com", organizationId: "org-1", role: "ADMIN" };
const ANALYST: RequestUser = { id: "u-analyst", email: "analyst@example.com", organizationId: "org-1", role: "ANALYST" };
const WS = "ws-1";
const WS2 = "ws-2";

function makeStack() {
  const prisma = makeFake();
  const audit = { record: mockFn(async () => ({})) };
  const frameworks = new FrameworkService(prisma as never, audit as never);
  const controls = new ControlService(prisma as never, audit as never);
  const evidence = new EvidenceService(prisma as never, audit as never, controls);
  const monitoring = new MonitoringService(prisma as never, audit as never, controls);
  const assessments = new AssessmentService(prisma as never, audit as never, controls, evidence);
  const risks = new RiskService(prisma as never, audit as never);
  const policies = new PolicyService(prisma as never, audit as never);
  const audits = new GrcAuditService(prisma as never, audit as never);
  const vendors = new VendorService(prisma as never, audit as never);
  const findingLinks = new FindingLinkService(prisma as never, audit as never, controls);
  const analytics = new GrcAnalyticsService(prisma as never, controls);
  const reports = new GrcReportService(prisma as never, audit as never, analytics);
  const backup = new GrcBackupService(prisma as never, audit as never);
  const ai = new AiGrcService(prisma as never);
  return { prisma, audit, frameworks, controls, evidence, monitoring, assessments, risks, policies, audits, vendors, findingLinks, analytics, reports, backup, ai };
}

async function importCatalogs(s: ReturnType<typeof makeStack>, keys: string[]) {
  for (const key of keys) await s.frameworks.importCatalogFramework(ADMIN, WS, key);
}

async function mfaControl(s: ReturnType<typeof makeStack>) {
  await s.controls.ensureCatalog(ADMIN, WS);
  const { items } = await s.controls.listControls(ADMIN, WS);
  return items.find((c) => c.code === "MFA-ENFORCEMENT")!;
}

/* ------------------------------------------------------------------ */

describe("framework import & versioning (§121/§122)", () => {
  it("imports a synthetic framework with hierarchy preserved", async () => {
    const s = makeStack();
    const fw = await s.frameworks.importFramework(ADMIN, WS, {
      key: "CUSTOM_X", name: "Custom Framework", publisher: "Test", version: "1.0",
      requirements: [
        { requirementId: "1", title: "Root", level: 1 },
        { requirementId: "1.1", parentRequirementId: "1", title: "Child", level: 2 },
      ],
    });
    expect(fw.requirements).toHaveLength(2);
    const child = fw.requirements.find((r) => r.requirementId === "1.1")!;
    expect(child.parentRequirementId).toBe("1");
    expect(child.level).toBe(2);
  });

  it("refuses re-import of a published version (immutable, §4)", async () => {
    const s = makeStack();
    await importCatalogs(s, ["PCI_DSS"]);
    await expect(s.frameworks.importCatalogFramework(ADMIN, WS, "PCI_DSS")).rejects.toThrow(/immutable/);
  });

  it("old assessments stay pinned to V1 after V2 is imported (§122)", async () => {
    const s = makeStack();
    await importCatalogs(s, ["PCI_DSS"]);
    const v1 = await s.frameworks.listFrameworks(ADMIN);
    const v1Row = v1.items.find((f) => f.key === "PCI_DSS")!;
    const assessment = await s.assessments.createAssessment(ADMIN, WS, { frameworkId: v1Row.id, name: "PCI 4.0 assessment" });
    expect(assessment.frameworkVersion).toBe("4.0");
    await s.frameworks.importFramework(ADMIN, WS, {
      key: "PCI_DSS", name: "PCI DSS", publisher: "PCI SSC", version: "4.1",
      requirements: [{ requirementId: "1", title: "Root", level: 1 }],
    });
    const after = await s.assessments.getAssessment(ADMIN, WS, assessment.id);
    expect(after.frameworkVersion).toBe("4.0");
  });
});

describe("control library & cross-framework mapping (§7/§12/§123)", () => {
  it("seeds the catalog and binds one control to many frameworks", async () => {
    const s = makeStack();
    await importCatalogs(s, ["ISO_27001", "PCI_DSS", "CIS_CONTROLS"]);
    const { items } = await s.controls.listControls(ADMIN, WS);
    expect(items.length).toBeGreaterThanOrEqual(25);
    const mfa = items.find((c) => c.code === "MFA-ENFORCEMENT")!;
    expect(mfa.mappingCount).toBeGreaterThanOrEqual(4); // ISO + PCI x2 + CIS x2 …
    const adminControls = items.filter((c) => c.implementationType === "ADMINISTRATIVE");
    for (const c of adminControls) {
      const detail = await s.controls.getControl(ADMIN, WS, c.id);
      expect(detail.tests[0]?.automationLevel).toBe("NONE");
    }
  });

  it("one evidence record serves two frameworks without duplication (§123)", async () => {
    const s = makeStack();
    await importCatalogs(s, ["ISO_27001", "PCI_DSS"]);
    const mfa = await mfaControl(s);
    await s.prisma.organizationSecurityPolicy.create({
      data: { id: "pol-1", organizationId: "org-1", mfaRequirement: "REQUIRED_FOR_ALL" } as never,
    });
    await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    const ev = await s.evidence.collect(ADMIN, WS, {
      controlId: mfa.id, sourceType: "MFA_CONFIGURATION", sourceId: "org-policy",
      snapshot: { mfaRequirement: "REQUIRED_FOR_ALL" },
    });
    const frameworks = await s.frameworks.listFrameworks(ADMIN);
    const referencedBy: string[] = [];
    for (const fw of frameworks.items) {
      const a = await s.assessments.createAssessment(ADMIN, WS, { frameworkId: fw.id, name: `${fw.key} check` });
      const { results } = await s.assessments.computeResults(ADMIN, WS, a.id);
      for (const r of results) if ((r.evidenceIds as string[]).includes(ev.id)) referencedBy.push(fw.key);
    }
    expect(referencedBy).toContain("ISO_27001");
    expect(referencedBy).toContain("PCI_DSS");
    const evidenceRows = await s.prisma.complianceEvidence.findMany({ where: { workspaceId: WS } });
    expect(evidenceRows).toHaveLength(1); // shared, never duplicated
  });

  it("a PARTIAL mapping at partial coverage yields at best PARTIALLY_COMPLIANT (§124)", async () => {
    const s = makeStack();
    await importCatalogs(s, ["NIST_800_53"]);
    const control = await s.controls.createControl(ADMIN, WS, {
      code: "CUSTOM-TECH", title: "Custom technical control", controlType: "PREVENTIVE", implementationType: "TECHNICAL",
    });
    const test = await s.prisma.controlTest.create({
      data: { id: "t-1", workspaceId: WS, controlId: control.id, name: "t", method: "AUTOMATED", automationLevel: "FULL", frequency: "CONTINUOUS", expectedResult: "", evidenceRequirements: "", signalKeys: ["custom.ok"] } as never,
    });
    void test;
    const ia2 = (await s.frameworks.getFramework(ADMIN, (await s.frameworks.listFrameworks(ADMIN)).items[0]!.id)).requirements
      .find((r) => r.requirementId === "IA-2")!;
    await s.controls.createMapping(ADMIN, WS, {
      controlId: control.id, requirementId: ia2.id, mappingType: "PARTIAL", coverage: 0.5,
    });
    await s.monitoring.recordSignal(ADMIN, WS, { controlId: control.id, signalKey: "custom.ok", state: "PASS" });
    const evaluation = await s.monitoring.evaluate(ADMIN, WS, control.id, ADMIN.id);
    expect(evaluation.evaluation.result).toBe("PASS");
    await s.evidence.collect(ADMIN, WS, {
      controlId: control.id, sourceType: "IDENTITY_POSTURE", sourceId: "fixture", snapshot: { ok: true },
    });
    const fw = (await s.frameworks.listFrameworks(ADMIN)).items[0]!;
    const a = await s.assessments.createAssessment(ADMIN, WS, { frameworkId: fw.id, name: "800-53 check" });
    const { results } = await s.assessments.computeResults(ADMIN, WS, a.id);
    const ia2Result = results.find((r) => r.requirementId === ia2.id)!;
    expect(ia2Result.result).toBe("PARTIALLY_COMPLIANT");
  });
});

describe("evidence immutability & freshness (§125/§126)", () => {
  it("completing an assessment snapshots evidence; later source changes do not alter it (§125)", async () => {
    const s = makeStack();
    await importCatalogs(s, ["ISO_27001"]);
    const mfa = await mfaControl(s);
    await s.prisma.organizationSecurityPolicy.create({
      data: { id: "pol-1", organizationId: "org-1", mfaRequirement: "REQUIRED_FOR_ALL" } as never,
    });
    await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    const ev = await s.evidence.collect(ADMIN, WS, {
      controlId: mfa.id, sourceType: "MFA_CONFIGURATION", sourceId: "org-policy",
      snapshot: { mfaRequirement: "REQUIRED_FOR_ALL" },
    });
    const fw = (await s.frameworks.listFrameworks(ADMIN)).items[0]!;
    const a = await s.assessments.createAssessment(ADMIN, WS, { frameworkId: fw.id, name: "ISO check" });
    const before = await s.assessments.computeResults(ADMIN, WS, a.id);
    const a85Before = before.results.find((r) => (r.evidenceIds as string[]).includes(ev.id))!;
    expect(a85Before).toBeTruthy();
    // Source configuration changes afterwards + control now FAILs.
    const policyRow = s.prisma.organizationSecurityPolicy.rows[0]!;
    policyRow.mfaRequirement = "OPTIONAL";
    await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    const stored = await s.assessments.getAssessment(ADMIN, WS, a.id);
    const a85After = stored.results.find((r) => r.id === a85Before.id)!;
    expect(a85After.result).toBe(a85Before.result);
    expect(a85After.evidenceIds).toEqual(a85Before.evidenceIds);
    const storedEvidence = await s.prisma.complianceEvidence.findFirst({ where: { id: ev.id } });
    expect(storedEvidence!.snapshot).toEqual({ mfaRequirement: "REQUIRED_FOR_ALL" });
    expect(storedEvidence!.hash).toBe(ev.hash);
  });

  it("freshness derives CURRENT → STALE → EXPIRED from the per-control policy (§126)", async () => {
    const s = makeStack();
    const control = await s.prisma.securityControl.create({
      data: { id: "c-fresh", workspaceId: WS, code: "FRESH", title: "t", controlType: "DETECTIVE", implementationType: "TECHNICAL", implementationStatus: "IMPLEMENTED", effectiveness: "EFFECTIVE" } as never,
    });
    await s.prisma.evidenceFreshnessPolicy.create({
      data: { id: "fp-1", workspaceId: WS, controlId: control.id, staleAfterDays: 30, expireAfterDays: 90 } as never,
    });
    const now = Date.now();
    const mk = (id: string, daysAgo: number) => s.prisma.complianceEvidence.create({
      data: {
        id, workspaceId: WS, controlId: control.id, sourceType: "MFA_CONFIGURATION", sourceId: id,
        snapshot: {}, classification: "INTERNAL", status: "CURRENT", hash: "h", createdBy: "u",
        reviewStatus: "NOT_REQUIRED", collectedAt: new Date(now - daysAgo * 86_400_000),
      } as never,
    });
    await mk("ev-fresh", 5);
    await mk("ev-stale", 45);
    await mk("ev-expired", 120);
    const { items } = await s.evidence.listEvidence(ADMIN, WS, control.id);
    const byId = new Map(items.map((i) => [i.id, (i as { derivedStatus: string }).derivedStatus]));
    expect(byId.get("ev-fresh")).toBe("CURRENT");
    expect(byId.get("ev-stale")).toBe("STALE");
    expect(byId.get("ev-expired")).toBe("EXPIRED");
  });
});

describe("continuous control monitoring (§127/§128/§139)", () => {
  it("MFA policy flip fails the control, emits drift, and recovery is recorded", async () => {
    const s = makeStack();
    const mfa = await mfaControl(s);
    await s.prisma.organizationSecurityPolicy.create({
      data: { id: "pol-1", organizationId: "org-1", mfaRequirement: "REQUIRED_FOR_ALL" } as never,
    });
    const first = await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    expect(first.evaluation.result).toBe("PASS");
    s.prisma.organizationSecurityPolicy.rows[0]!.mfaRequirement = "OPTIONAL";
    const second = await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    expect(second.evaluation.result).toBe("FAIL");
    let drift = await s.monitoring.listDrift(ADMIN, WS);
    expect(drift.items.some((d) => d.type === "CONTROL_FAILED")).toBe(true);
    s.prisma.organizationSecurityPolicy.rows[0]!.mfaRequirement = "REQUIRED_FOR_ALL";
    const third = await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    expect(third.evaluation.result).toBe("PASS");
    drift = await s.monitoring.listDrift(ADMIN, WS);
    expect(drift.items.some((d) => d.type === "CONTROL_RECOVERED")).toBe(true);
    const actions = s.audit.record.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("CONTROL_FAILED");
    expect(actions).toContain("CONTROL_RECOVERED");
  });

  it("a signal change re-evaluates only the affected controls (§139)", async () => {
    const s = makeStack();
    await s.controls.ensureCatalog(ADMIN, WS);
    const out = await s.monitoring.reevaluateForSignals(ADMIN, WS, ["identity.mfa_enforced"]);
    expect(out.reevaluated).toBe(1);
    const code = (await s.prisma.securityControl.findFirst({ where: { id: out.controlIds[0] } }))!.code;
    expect(code).toBe("MFA-ENFORCEMENT");
  });

  it("no policy data → control is INCONCLUSIVE, never PASS", async () => {
    const s = makeStack();
    const mfa = await mfaControl(s);
    const out = await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    expect(out.evaluation.result).toBe("INCONCLUSIVE");
  });
});

describe("risk register (§129–§131)", () => {
  it("computes inherent risk deterministically and residual only with known effectiveness (§129/§49)", async () => {
    const s = makeStack();
    const plain = await s.risks.createRisk(ADMIN, WS, {
      title: "Unlinked risk", source: "MANUAL", likelihood: 4, impacts: { confidentiality: 5 },
    });
    expect(plain.inherentScore).toBe(20);
    expect(plain.inherentBand).toBe("CRITICAL");
    expect(plain.residualScore).toBeNull();

    const control = await s.prisma.securityControl.create({
      data: { id: "c-eff", workspaceId: WS, code: "EFF", title: "t", controlType: "PREVENTIVE", implementationType: "TECHNICAL", implementationStatus: "IMPLEMENTED", effectiveness: "EFFECTIVE" } as never,
    });
    const linked = await s.risks.createRisk(ADMIN, WS, {
      title: "Linked risk", source: "MANUAL", likelihood: 4, impacts: { confidentiality: 4 },
      links: [{ linkType: "CONTROL", linkId: control.id }],
    });
    expect(linked.inherentScore).toBe(16);
    expect(linked.residualScore).toBe(6);
    expect(linked.residualBand).toBe("MEDIUM");
  });

  it("segregation of duties denies self-approval of a high-risk acceptance (§130)", async () => {
    const s = makeStack();
    const risk = await s.risks.createRisk(ADMIN, WS, {
      title: "High risk", source: "MANUAL", likelihood: 5, impacts: { financial: 5 },
    });
    const acceptance = await s.risks.requestAcceptance(ADMIN, WS, risk.id, {
      reason: "business need", expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    });
    await expect(
      s.risks.decideAcceptance(ADMIN, WS, risk.id, acceptance.id, { decision: "ACCEPTED" }),
    ).rejects.toThrow(/Segregation of duties/);
    const decided = await s.risks.decideAcceptance(ADMIN2, WS, risk.id, acceptance.id, { decision: "ACCEPTED" });
    expect(decided.status).toBe("ACCEPTED");
    const after = await s.risks.getRisk(ADMIN, WS, risk.id);
    expect(after.status).toBe("ACCEPTED");
  });

  it("an expired acceptance returns the risk to review (§131)", async () => {
    const s = makeStack();
    const risk = await s.risks.createRisk(ADMIN, WS, {
      title: "Expiring", source: "MANUAL", likelihood: 2, impacts: { operational: 2 },
    });
    const acceptance = await s.risks.requestAcceptance(ADMIN, WS, risk.id, {
      reason: "temporary", expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
    });
    await s.risks.decideAcceptance(ADMIN2, WS, risk.id, acceptance.id, { decision: "ACCEPTED" });
    await s.risks.listRisks(ADMIN, WS); // triggers the expiry sweep
    const after = await s.risks.getRisk(ADMIN, WS, risk.id);
    expect(after.status).toBe("ASSESSED");
    expect(after.acceptances[0]!.status).toBe("EXPIRED");
  });

  it("treatment plans move a risk to TREATMENT_PLANNED with tracked actions", async () => {
    const s = makeStack();
    const risk = await s.risks.createRisk(ADMIN, WS, {
      title: "Treat me", source: "CONTROL_FAILURE", likelihood: 3, impacts: { integrity: 3 },
    });
    const plan = await s.risks.createTreatment(ADMIN, WS, risk.id, {
      strategy: "MITIGATE", actions: [{ action: "Fix the control", dueDate: new Date(Date.now() + 7 * 86_400_000).toISOString() }],
    });
    expect(plan.actions).toHaveLength(1);
    const after = await s.risks.getRisk(ADMIN, WS, risk.id);
    expect(after.status).toBe("TREATMENT_PLANNED");
    expect(after.treatment).toBe("MITIGATE");
  });
});

describe("hostile manual evidence (§136) & review SoD (§38/§111)", () => {
  const pdfB64 = Buffer.from("%PDF-1.7\nfixture").toString("base64");
  it("rejects HTML, archives and mismatched content; accepts a real PDF as PENDING review", async () => {
    const s = makeStack();
    const control = await mfaControl(s);
    await expect(s.evidence.upload(ADMIN, WS, {
      controlId: control.id, filename: "evil.pdf", contentType: "application/pdf",
      contentBase64: Buffer.from("<script>alert(1)</script>").toString("base64"),
    })).rejects.toThrow(/rejected/);
    await expect(s.evidence.upload(ADMIN, WS, {
      controlId: control.id, filename: "../../bomb.pdf", contentType: "application/pdf",
      contentBase64: Buffer.from("PK\x03\x04archive").toString("base64"),
    })).rejects.toThrow(/rejected/);
    const ok = await s.evidence.upload(ADMIN, WS, {
      controlId: control.id, filename: "policy.pdf", contentType: "application/pdf", contentBase64: pdfB64,
    });
    expect(ok.reviewStatus).toBe("PENDING");
    expect(ok.filename).toBe("policy.pdf");
    await expect(s.evidence.review(ADMIN, WS, ok.id, { decision: "APPROVED" })).rejects.toThrow(/Segregation of duties/);
    const reviewed = await s.evidence.review(ADMIN2, WS, ok.id, { decision: "APPROVED" });
    expect(reviewed.reviewStatus).toBe("APPROVED");
  });

  it("restricted evidence content is withheld from roles without VIEW_RESTRICTED_EVIDENCE (§41)", async () => {
    const s = makeStack();
    const control = await mfaControl(s);
    await s.evidence.collect(ANALYST, WS, {
      controlId: control.id, sourceType: "IDENTITY_POSTURE", sourceId: "x",
      snapshot: { secretShape: "do-not-leak" }, classification: "RESTRICTED",
    });
    const { items } = await s.evidence.listEvidence(ANALYST, WS, control.id);
    const restricted = items.find((i) => i.classification === "RESTRICTED")!;
    expect((restricted as { snapshot?: unknown }).snapshot).toBeUndefined();
    const { items: adminItems } = await s.evidence.listEvidence(ADMIN, WS, control.id);
    expect((adminItems[0] as { snapshot?: unknown }).snapshot).toBeDefined();
  });
});

describe("audit packages (§132/§133) and auditor access (§134/§135)", () => {
  async function packagedStack() {
    const s = makeStack();
    await importCatalogs(s, ["PCI_DSS"]);
    const mfa = await mfaControl(s);
    await s.prisma.organizationSecurityPolicy.create({
      data: { id: "pol-1", organizationId: "org-1", mfaRequirement: "REQUIRED_FOR_ALL" } as never,
    });
    await s.monitoring.evaluate(ADMIN, WS, mfa.id, ADMIN.id);
    await s.evidence.collect(ADMIN, WS, {
      controlId: mfa.id, sourceType: "MFA_CONFIGURATION", sourceId: "org-policy",
      snapshot: { mfaRequirement: "REQUIRED_FOR_ALL", api_key: "fixture-secret-value-123" },
    });
    const fw = (await s.frameworks.listFrameworks(ADMIN)).items[0]!;
    const assessment = await s.assessments.createAssessment(ADMIN, WS, { frameworkId: fw.id, name: "PCI audit scope" });
    await s.assessments.computeResults(ADMIN, WS, assessment.id);
    const audit = await s.audits.createAudit(ADMIN, WS, { type: "EXTERNAL", auditorRef: "External assessor" });
    return { s, assessment, audit };
  }

  it("generates a CONFIDENTIAL package with a valid integrity manifest and redacted content (§132)", async () => {
    const { s, assessment, audit } = await packagedStack();
    const pkg = await s.audits.generatePackage(ADMIN, WS, audit.id, assessment.id);
    expect(pkg.classification).toBe("CONFIDENTIAL");
    expect(pkg.frameworkVersion).toBe("4.0");
    const bundleText = JSON.stringify(pkg.bundle);
    expect(bundleText).not.toContain("fixture-secret-value-123");
    expect(bundleText).toContain("[REDACTED]");
    const verification = await s.audits.verifyPackageIntegrity(ADMIN, WS, pkg.id);
    expect(verification.valid).toBe(true);
  });

  it("tampering with packaged evidence fails integrity verification (§133)", async () => {
    const { s, assessment, audit } = await packagedStack();
    const pkg = await s.audits.generatePackage(ADMIN, WS, audit.id, assessment.id);
    const row = s.prisma.auditEvidencePackage.rows.find((r) => r.id === pkg.id)!;
    const bundle = row.bundle as Record<string, string>;
    const key = Object.keys(bundle).find((k) => k.startsWith("evidence/"))!;
    bundle[key] = bundle[key]!.replace("REQUIRED_FOR_ALL", "OPTIONAL");
    const verification = await s.audits.verifyPackageIntegrity(ADMIN, WS, pkg.id);
    expect(verification.valid).toBe(false);
    expect(verification.failures.join(" ")).toMatch(/integrity failure/);
  });

  it("auditor grants are explicit-share only and expire (§134/§135)", async () => {
    const { s, assessment } = await packagedStack();
    const auditor: RequestUser = { id: "u-auditor", email: "auditor@external.example", organizationId: "org-1", role: "VIEWER" };
    expect(await s.evidence.auditorCanAccess(auditor, WS, "assessment", assessment.id)).toBe(false);
    const grant = await s.audits.grantAuditorAccess(ADMIN, WS, {
      userId: auditor.id, assessmentIds: [assessment.id],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    });
    expect(await s.evidence.auditorCanAccess(auditor, WS, "assessment", assessment.id)).toBe(true);
    expect(await s.evidence.auditorCanAccess(auditor, WS, "assessment", "some-other-assessment")).toBe(false);
    await s.prisma.auditorAccessGrant.update({ where: { id: grant.id }, data: { expiresAt: new Date(Date.now() - 1000) } as never });
    expect(await s.evidence.auditorCanAccess(auditor, WS, "assessment", assessment.id)).toBe(false);
  });

  it("audit findings stay separate from technical findings (§69/§70)", async () => {
    const { s, audit } = await packagedStack();
    await s.prisma.finding.create({
      data: { id: "f-1", workspaceId: WS, scanId: "scan-1", title: "TLS weak", description: "", severity: "HIGH", status: "OPEN" } as never,
    });
    const af = await s.audits.createFinding(ADMIN, WS, audit.id, {
      title: "TLS governance gap", ownerId: ADMIN.id, linkedFindingIds: ["f-1"],
    });
    expect(af.id).not.toBe("f-1");
    const findings = await s.prisma.finding.findMany({ where: { workspaceId: WS } });
    expect(findings).toHaveLength(1); // technical finding untouched, not merged
  });
});

describe("finding → control linkage (§84–§87)", () => {
  it("suggests and links deterministically, and an analyst override replaces with audit trail", async () => {
    const s = makeStack();
    await s.controls.ensureCatalog(ADMIN, WS);
    await s.prisma.finding.create({
      data: { id: "f-tls", workspaceId: WS, scanId: "scan-1", title: "Cleartext HTTP", description: "", severity: "MEDIUM", status: "OPEN", cwe: "CWE-319", sources: ["testssl"] } as never,
    });
    const { suggestion } = await s.findingLinks.suggestForFinding(ADMIN, WS, "f-tls");
    expect(suggestion?.controlCode).toBe("ENCRYPTION-IN-TRANSIT");
    const link = await s.findingLinks.linkFinding(ADMIN, WS, "f-tls");
    expect(link.origin).toBe("AUTOMATIC");
    const { items } = await s.controls.listControls(ADMIN, WS);
    const other = items.find((c) => c.code === "LOGGING-MONITORING")!;
    const overridden = await s.findingLinks.overrideLink(ADMIN, WS, "f-tls", { controlId: other.id, rationale: "TLS termination is logged centrally" });
    expect(overridden.origin).toBe("ANALYST_OVERRIDE");
    const actions = s.audit.record.calls.map((c) => (c[0] as { metadata?: { override?: boolean } }).metadata?.override);
    expect(actions).toContain(true);
  });
});

describe("AI GRC assistant (§137/§138)", () => {
  it("never claims certification without an approved certification record (§137)", async () => {
    const s = makeStack();
    const out = await s.ai.ask(ADMIN, WS, { question: "Are we ISO certified?" });
    expect(out.certificationClaimBlocked).toBe(true);
    expect(out.text).not.toMatch(/you are certified/i);
  });

  it("answers INSUFFICIENT_EVIDENCE when a control has no evidence (§138)", async () => {
    const s = makeStack();
    const mfa = await mfaControl(s);
    const out = await s.ai.ask(ADMIN, WS, {
      question: "Why did this control pass? Justify it with evidence.", controlId: mfa.id,
    });
    expect(out.insufficientEvidence).toBe(true);
    expect(out.text).toContain("INSUFFICIENT_EVIDENCE");
  });
});

describe("cross-tenant isolation (§140)", () => {
  it("workspace B cannot read workspace A's GRC records", async () => {
    const s = makeStack();
    const risk = await s.risks.createRisk(ADMIN, WS, {
      title: "Tenant A risk", source: "MANUAL", likelihood: 3, impacts: { confidentiality: 3 },
    });
    await expect(s.risks.getRisk(ADMIN, WS2, risk.id)).rejects.toThrow(/not found/);
    const { items } = await s.evidence.listEvidence(ADMIN, WS2);
    expect(items).toHaveLength(0);
    const control = await mfaControl(s);
    await expect(s.controls.getControl(ADMIN, WS2, control.id)).rejects.toThrow(/not found/);
    await expect(s.assessments.getAssessment(ADMIN, WS2, "anything")).rejects.toThrow(/not found/);
    const vendorsB = await s.vendors.listVendors(ADMIN, WS2);
    expect(vendorsB.items).toHaveLength(0);
  });
});

describe("backup / restore (§141)", () => {
  it("exports and restores GRC state with evidence hashes intact; tampered bundles are refused", async () => {
    const s = makeStack();
    const control = await mfaControl(s);
    const ev = await s.evidence.collect(ADMIN, WS, {
      controlId: control.id, sourceType: "MFA_CONFIGURATION", sourceId: "org-policy",
      snapshot: { mfaRequirement: "REQUIRED_FOR_ALL" },
    });
    await s.risks.createRisk(ADMIN, WS, { title: "Backup risk", source: "MANUAL", likelihood: 2, impacts: { availability: 2 } });
    const bundle = await s.backup.exportState(ADMIN, WS);
    const restored = await s.backup.restoreState(ADMIN, WS2, bundle as never);
    expect(restored.restored.securityControl).toBeGreaterThan(0);
    expect(restored.restored.complianceEvidence).toBe(1);
    const restoredEvidence = await s.prisma.complianceEvidence.findFirst({ where: { workspaceId: WS2 } });
    expect(restoredEvidence!.hash).toBe(ev.hash);
    const tampered = { ...bundle, hash: "deadbeef" };
    await expect(s.backup.restoreState(ADMIN, WS2, tampered as never)).rejects.toThrow(/integrity check failed/);
  });
});

describe("policies, vendors, reports & dashboards (§60–§63/§106–§108/§114–§117/§76–§83)", () => {
  it("policy lifecycle is versioned and acknowledgements are explicit", async () => {
    const s = makeStack();
    const policy = await s.policies.createPolicy(ADMIN, WS, { title: "Access Control Policy", version: "1.0" });
    await expect(s.policies.createPolicy(ADMIN, WS, { title: "Access Control Policy", version: "1.0" })).rejects.toThrow(/immutable/);
    await s.policies.transitionPolicy(ADMIN, WS, policy.id, { status: "APPROVED" });
    const active = await s.policies.transitionPolicy(ADMIN, WS, policy.id, { status: "ACTIVE" });
    expect(active.status).toBe("ACTIVE");
    const ack = await s.policies.acknowledge(ANALYST, WS, policy.id);
    expect(ack.userId).toBe(ANALYST.id);
    const actions = s.audit.record.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("POLICY_APPROVED");
  });

  it("vendor assessments update the vendor rating", async () => {
    const s = makeStack();
    const vendor = await s.vendors.createVendor(ADMIN, WS, { name: "Example Cloud Ltd", criticality: "HIGH" });
    expect(vendor.riskRating).toBeNull();
    await s.vendors.assessVendor(ADMIN, WS, vendor.id, { riskRating: "MEDIUM", findings: "SOC 2 report reviewed" });
    const { items } = await s.vendors.listVendors(ADMIN, WS);
    expect(items[0]!.riskRating).toBe("MEDIUM");
  });

  it("issued reports are immutable snapshots with redaction and CSV/JSON export", async () => {
    const s = makeStack();
    await s.risks.createRisk(ADMIN, WS, {
      title: "Report risk Bearer fixture-token-value-123", source: "MANUAL", likelihood: 3, impacts: { confidentiality: 3 },
    });
    const report = await s.reports.generateReport(ADMIN, WS, { reportType: "RISK_REGISTER" });
    expect(JSON.stringify(report.content)).not.toContain("fixture-token-value-123");
    expect(JSON.stringify(report.content)).toContain("[REDACTED]");
    const json = await s.reports.exportReport(ADMIN, WS, report.id, "json");
    expect(json.format).toBe("json");
    const csvOut = await s.reports.exportReport(ADMIN, WS, report.id, "csv");
    expect(csvOut.content as string).toContain("section,key,value");
  });

  it("compliance dashboard reports coverage honestly (labelled, not a certification)", async () => {
    const s = makeStack();
    await importCatalogs(s, ["ISO_27001"]);
    const dash = await s.analytics.complianceDashboard(ADMIN, WS);
    expect(dash.coverageLabel).toMatch(/not a certification/);
    expect(dash.disclaimer).toMatch(/does not certify/);
    expect(dash.overallAssessmentStatus).toBe("NOT_STARTED");
  });
});
