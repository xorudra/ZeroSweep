import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  evaluateControl, type ControlSignalData,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import { ControlService } from "../controls/control.service";
import type { RecordSignalInput } from "../dto/schemas";

const OPEN_FINDING_STATES = ["OPEN", "CONFIRMED"];
const CLOUD_FRAMEWORKS = ["CIS_AWS", "CIS_AZURE", "CIS_GCP"];
const K8S_FRAMEWORKS = ["CIS_KUBERNETES", "NSA_CISA_KUBERNETES"];

/**
 * Continuous control monitoring (Prompt 26 §26–§32, §94/§95).
 * Signals are DERIVED from real platform state — identity policy
 * (Prompt 23), posture snapshots (Prompt 22), posture control
 * assessments (Prompts 13/14) and canonical findings — or recorded as
 * observations by authorized callers. Derivation never invents a
 * state: when no authoritative data exists the signal is null and the
 * control evaluates INCONCLUSIVE. Collection never starts a scan
 * (§27 — no hidden scans); re-evaluation only re-reads state.
 */
@Injectable()
export class MonitoringService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly controls: ControlService,
  ) {}

  /* --------------------------- signal intake --------------------------- */

  async recordSignal(user: RequestUser, workspaceId: string, input: RecordSignalInput) {
    requireGrcPermission(user, "TEST_CONTROLS");
    await this.controls.findControl(workspaceId, input.controlId);
    const row = await this.prisma.controlSignal.create({
      data: {
        workspaceId, controlId: input.controlId, signalKey: input.signalKey, state: input.state,
        detail: input.detail ?? "", sourceType: input.sourceType ?? "OBSERVATION",
        evidenceRefs: input.evidenceRefs ?? [],
      },
    });
    return row;
  }

  async listSignals(user: RequestUser, workspaceId: string, controlId: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const items = await this.prisma.controlSignal.findMany({
      where: { workspaceId, controlId }, orderBy: { observedAt: "desc" }, take: 100,
    });
    return { items, total: items.length };
  }

  /* -------------------------- signal derivation ------------------------- */

  /** Latest posture-assessment verdict per framework family, optionally
   *  restricted to CIS section prefixes (documented public mapping:
   *  CIS AWS Foundations 1.x IAM, 2.x storage, 3.x logging, 4.x network). */
  private async postureSignal(frameworkKeys: string[], sectionPrefixes?: string[]) {
    const rows = await this.prisma.controlAssessment.findMany({
      where: { frameworkKey: { in: frameworkKeys } },
      orderBy: { assessedAt: "desc" }, take: 500,
    });
    const scoped = sectionPrefixes
      ? rows.filter((r) => sectionPrefixes.some((p) => (r.controlId as string).startsWith(p)))
      : rows;
    if (scoped.length === 0) return null;
    const latest = new Map<string, string>();
    for (const r of scoped) {
      const key = `${r.frameworkKey}:${r.controlId}:${r.subjectRef}`;
      if (!latest.has(key)) latest.set(key, r.status as string);
    }
    const states = [...latest.values()];
    if (states.includes("FAIL")) return "FAIL" as const;
    if (states.includes("WARN")) return "PARTIAL" as const;
    return "PASS" as const;
  }

  private async findingSignal(workspaceId: string, predicate: (f: Record<string, unknown>) => boolean) {
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 2000,
    });
    if (findings.length === 0) return null; // no scan data at all → unknown, never PASS
    const open = findings.filter((f) => OPEN_FINDING_STATES.includes(f.status as string));
    return open.some((f) => predicate(f as Record<string, unknown>)) ? ("FAIL" as const) : ("PASS" as const);
  }

  /** Derive the current signal states for one control from platform state. */
  async deriveSignals(user: RequestUser, workspaceId: string, controlId: string): Promise<ControlSignalData[]> {
    const control = await this.controls.findControl(workspaceId, controlId);
    const tests = await this.prisma.controlTest.findMany({ where: { workspaceId, controlId } });
    const keys = [...new Set(tests.flatMap((t) => (Array.isArray(t.signalKeys) ? (t.signalKeys as string[]) : [])))];
    const orgId = user.organizationId;
    const now = new Date().toISOString();
    const out: ControlSignalData[] = [];
    const push = (key: string, state: "PASS" | "FAIL" | "PARTIAL" | null, detail: string, refs: string[] = []) =>
      out.push({ key, state, detail, evidenceRefs: refs, observedAt: now });

    const orgPolicy = await this.prisma.organizationSecurityPolicy.findFirst({ where: { organizationId: orgId } });
    const passwordPolicy = await this.prisma.passwordPolicy.findFirst({ where: { organizationId: orgId } });
    const snapshot = await this.prisma.securityPostureSnapshot.findFirst({
      where: { workspaceId }, orderBy: { capturedAt: "desc" },
    });

    for (const key of keys) {
      switch (key) {
        case "identity.mfa_enforced":
          if (!orgPolicy) push(key, null, "No organization security policy recorded");
          else if (orgPolicy.mfaRequirement === "REQUIRED_FOR_ALL") push(key, "PASS", "MFA required for all users (organization policy)", [orgPolicy.id]);
          else if (orgPolicy.mfaRequirement === "REQUIRED_FOR_ADMINS") push(key, "PARTIAL", "MFA required for admins only", [orgPolicy.id]);
          else push(key, "FAIL", "MFA is OPTIONAL in the organization policy", [orgPolicy.id]);
          break;
        case "identity.admin_phishing_resistant_mfa": {
          const creds = await this.prisma.webAuthnCredential.count({ where: {} }).catch(() => 0);
          push(key, creds > 0 ? "PARTIAL" : null, creds > 0
            ? "WebAuthn credentials exist in the organization; per-admin coverage requires access-review evidence"
            : "No WebAuthn credentials recorded");
          break;
        }
        case "identity.sso_configured": {
          const provider = await this.prisma.enterpriseSsoProvider.findFirst({ where: { organizationId: orgId, enabled: true } });
          if (provider) push(key, provider.enforceSso ? "PASS" : "PARTIAL", `SSO provider ${provider.name} enabled (enforceSso=${provider.enforceSso})`, [provider.id]);
          else push(key, orgPolicy ? "FAIL" : null, orgPolicy ? "No enabled SSO provider" : "No organization policy or SSO provider recorded");
          break;
        }
        case "identity.password_policy_compliant":
          if (!passwordPolicy) push(key, null, "No password policy recorded");
          else push(key, passwordPolicy.minLength >= 12 && passwordPolicy.compromisedCheckEnabled ? "PASS" : "PARTIAL",
            `minLength=${passwordPolicy.minLength}, compromisedCheck=${passwordPolicy.compromisedCheckEnabled}`, [passwordPolicy.id]);
          break;
        case "identity.access_review_current": {
          const review = await this.prisma.accessReview.findFirst({
            where: { organizationId: orgId, status: "COMPLETED" }, orderBy: { completedAt: "desc" },
          });
          if (!review?.completedAt) push(key, null, "No completed access review recorded");
          else {
            const ageDays = (Date.now() - new Date(review.completedAt).getTime()) / 86_400_000;
            push(key, ageDays <= 100 ? "PASS" : "FAIL", `Last access review completed ${Math.floor(ageDays)} days ago`, [review.id]);
          }
          break;
        }
        case "vuln.scan_coverage":
          if (!snapshot || snapshot.coverage === null || snapshot.coverage === undefined) push(key, null, "No posture snapshot with coverage data");
          else push(key, snapshot.coverage >= 0.95 ? "PASS" : snapshot.coverage >= 0.7 ? "PARTIAL" : "FAIL", `Scan coverage ${(snapshot.coverage * 100).toFixed(0)}%`, [snapshot.id]);
          break;
        case "vuln.sla_compliance":
          if (!snapshot) push(key, null, "No posture snapshot recorded");
          else push(key, snapshot.slaOverdue > 0 ? "FAIL" : "PASS", `SLA overdue findings: ${snapshot.slaOverdue}`, [snapshot.id]);
          break;
        case "vuln.kev_open":
          if (!snapshot) push(key, null, "No posture snapshot recorded");
          else push(key, snapshot.kevCount > 0 ? "FAIL" : "PASS", `Known-exploited open findings: ${snapshot.kevCount}`, [snapshot.id]);
          break;
        case "crypto.tls_findings":
          push(key, await this.findingSignal(workspaceId, (f) =>
            ["CWE-319", "CWE-295", "CWE-327"].includes((f.cwe as string) ?? "") ||
            /tls|ssl|cleartext/i.test((f.vulnClass as string) ?? "")), "Open TLS/cleartext findings");
          break;
        case "code.secrets_open":
          push(key, await this.findingSignal(workspaceId, (f) =>
            ["CWE-798", "CWE-259", "CWE-321"].includes((f.cwe as string) ?? "") ||
            /secret|credential/i.test((f.vulnClass as string) ?? "")), "Open secret findings");
          break;
        case "code.vulnerable_components_open":
          push(key, await this.findingSignal(workspaceId, (f) =>
            ["CWE-1035", "CWE-1104"].includes((f.cwe as string) ?? "") ||
            ((f.severity as string) === "CRITICAL" && /component|dependency|sca/i.test((f.vulnClass as string) ?? ""))), "Open critical vulnerable-component findings");
          break;
        case "code.sbom_current": {
          // SBOMs bind to snapshots/images/builds (Prompt 12/13), which
          // bind to scans in this workspace — presence of any SBOM on a
          // workspace scan is the coverage signal.
          const scans = await this.prisma.scan.findMany({ where: { workspaceId }, select: { id: true }, take: 500 });
          const sbom = scans.length === 0 ? null : await this.prisma.softwareBillOfMaterials.findFirst({
            where: { scanId: { in: scans.map((s) => s.id) } }, orderBy: { createdAt: "desc" },
          }).catch(() => null);
          push(key, sbom ? "PASS" : null, sbom ? "An SBOM exists for a workspace scan" : "No SBOM recorded for workspace scans");
          break;
        }
        case "container.critical_findings_open":
          push(key, await this.findingSignal(workspaceId, (f) =>
            ((f.sources as string[]) ?? []).some((s) => /trivy|grype/i.test(s)) && (f.severity as string) === "CRITICAL"), "Open critical container findings");
          break;
        case "api.critical_findings_open":
          push(key, await this.findingSignal(workspaceId, (f) =>
            ((f.sources as string[]) ?? []).some((s) => /schemathesis|inql|zap/i.test(s)) && (f.severity as string) === "CRITICAL"), "Open critical API findings");
          break;
        case "k8s.posture_failures_open": {
          const state = await this.postureSignal(K8S_FRAMEWORKS);
          push(key, state, "Kubernetes posture control assessments (CIS/NSA-CISA)");
          break;
        }
        case "cloud.encryption_at_rest": {
          const state = await this.postureSignal(CLOUD_FRAMEWORKS, ["2."]);
          push(key, state, "Cloud storage posture section (CIS x.2) — encryption & exposure checks");
          break;
        }
        case "cloud.public_exposure": {
          const state = await this.postureSignal(CLOUD_FRAMEWORKS, ["2."]);
          push(key, state, "Cloud storage posture section (CIS x.2) — public-access checks");
          break;
        }
        case "cloud.iam_findings_open": {
          const state = await this.postureSignal(CLOUD_FRAMEWORKS, ["1."]);
          push(key, state, "Cloud IAM posture section (CIS x.1)");
          break;
        }
        case "cloud.logging_enabled": {
          const state = await this.postureSignal(CLOUD_FRAMEWORKS, ["3."]);
          push(key, state === "FAIL" ? "FAIL" : state, "Cloud logging posture section (CIS x.3)");
          break;
        }
        case "network.exposure_findings_open":
          push(key, await this.findingSignal(workspaceId, (f) =>
            /expos|management interface|unauthenticated/i.test((f.vulnClass as string) ?? "")), "Open network exposure findings");
          break;
        case "platform.audit_logging_active": {
          const count = await this.prisma.auditLog.count({ where: { organizationId: orgId } });
          push(key, count > 0 ? "PASS" : null, count > 0 ? "Audit events are being recorded" : "No audit events recorded");
          break;
        }
        case "devsecops.gates_enforced": {
          const gates = await this.prisma.qualityGateResult.count({ where: {} }).catch(() => 0);
          const policies = await this.prisma.repositorySecurityPolicy.count({ where: { workspaceId } }).catch(() => 0);
          if (policies > 0) push(key, gates > 0 ? "PASS" : "PARTIAL", `Repository security policies: ${policies}, gate evaluations: ${gates}`);
          else push(key, null, "No repository security policy recorded");
          break;
        }
        default:
          // Recorded observations (e.g. backup verification, DR tests)
          // are read from ControlSignal rows by evaluate() — derivation
          // has no authoritative source, so the state stays unknown.
          push(key, null, "No derivation source; awaiting a recorded observation or evidence");
      }
    }
    // Controls without catalog tests: fall back to their recorded signals.
    if (keys.length === 0) {
      const recorded = await this.prisma.controlSignal.findMany({
        where: { workspaceId, controlId }, orderBy: { observedAt: "desc" }, take: 50,
      });
      const seen = new Set<string>();
      for (const r of recorded) {
        if (seen.has(r.signalKey)) continue;
        seen.add(r.signalKey);
        out.push({ key: r.signalKey, state: r.state as ControlSignalData["state"], detail: r.detail, evidenceRefs: (r.evidenceRefs as string[]) ?? [], observedAt: new Date(r.observedAt).toISOString() });
      }
    }
    return out;
  }

  /* ----------------------------- evaluation ----------------------------- */

  /** Evaluate one control now: derive signals, persist signals where
   *  they came from derivation, run the SDK evaluator, persist the
   *  evaluation, update control effectiveness, and emit drift events
   *  on PASS↔FAIL transitions (§94/§95/§139 — only this control is
   *  re-evaluated, never a full assessment rerun). */
  async evaluate(user: RequestUser, workspaceId: string, controlId: string, evaluatedBy = "SYSTEM") {
    requireGrcPermission(user, "TEST_CONTROLS");
    const control = await this.controls.findControl(workspaceId, controlId);
    const tests = await this.prisma.controlTest.findMany({ where: { workspaceId, controlId } });
    const requiredKeys = [...new Set(tests.flatMap((t) => (Array.isArray(t.signalKeys) ? (t.signalKeys as string[]) : [])))];
    const derived = await this.deriveSignals(user, workspaceId, controlId);

    // Merge: latest recorded observation wins over derivation for the
    // same key when it is newer (observations are explicit evidence).
    const recorded = await this.prisma.controlSignal.findMany({
      where: { workspaceId, controlId }, orderBy: { observedAt: "desc" }, take: 200,
    });
    const byKey = new Map<string, ControlSignalData>();
    for (const s of derived) byKey.set(s.key, s);
    const seenRecorded = new Set<string>();
    for (const r of recorded) {
      if (seenRecorded.has(r.signalKey)) continue;
      seenRecorded.add(r.signalKey);
      const d = byKey.get(r.signalKey);
      if (!d || new Date(r.observedAt).getTime() >= new Date(d.observedAt).getTime()) {
        byKey.set(r.signalKey, {
          key: r.signalKey, state: r.state as ControlSignalData["state"], detail: r.detail,
          evidenceRefs: (r.evidenceRefs as string[]) ?? [], observedAt: new Date(r.observedAt).toISOString(),
        });
      }
    }
    const signals = [...byKey.values()];
    const outcome = evaluateControl(signals, requiredKeys);

    const previous = await this.prisma.controlEvaluation.findFirst({
      where: { workspaceId, controlId }, orderBy: { evaluatedAt: "desc" },
    });
    const evaluation = await this.prisma.controlEvaluation.create({
      data: {
        workspaceId, controlId, result: outcome.result, confidence: outcome.confidence,
        effectiveness: outcome.effectiveness, reason: outcome.reason,
        evidenceRefs: signals.flatMap((s) => s.evidenceRefs), evaluatedBy,
      },
    });
    await this.prisma.securityControl.update({
      where: { id: controlId }, data: { effectiveness: outcome.effectiveness },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_TESTED", resourceType: "SecurityControl", resourceId: controlId,
      metadata: { result: outcome.result, confidence: outcome.confidence },
    });
    // Drift (§95): FAIL transitions and recoveries are first-class events.
    if (previous && previous.result !== outcome.result) {
      if (outcome.result === "FAIL" && previous.result !== "FAIL") {
        await this.emitDrift(user, workspaceId, controlId, "CONTROL_FAILED", previous.result, outcome.result, outcome.reason);
      } else if (previous.result === "FAIL" && outcome.result === "PASS") {
        await this.emitDrift(user, workspaceId, controlId, "CONTROL_RECOVERED", previous.result, outcome.result, outcome.reason);
      }
    }
    if (outcome.result === "FAIL" && (!previous || previous.result !== "FAIL")) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "CONTROL_FAILED", resourceType: "SecurityControl", resourceId: controlId,
        metadata: { reason: outcome.reason },
      });
    }
    if (outcome.result === "PASS" && previous?.result === "FAIL") {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "CONTROL_RECOVERED", resourceType: "SecurityControl", resourceId: controlId, metadata: {},
      });
    }
    return { control: { id: control.id, code: control.code }, evaluation, signals };
  }

  private async emitDrift(user: RequestUser, workspaceId: string, controlId: string, type: string, prev: string, next: string, detail: string) {
    await this.prisma.complianceDriftEvent.create({
      data: { workspaceId, controlId, type, detail, previousResult: prev, newResult: next },
    });
    // §96: route through the platform notification router's IN_APP
    // channel by persisting a notification record (delivery honesty:
    // in-app is real delivery; external providers stay NOT_CONFIGURED).
    await this.prisma.notification.create({
      data: {
        workspaceId, userId: user.id,
        type: "SYSTEM", title: `GRC drift: ${type}`,
        body: `${detail} (control ${controlId}: ${prev} → ${next})`,
      },
    }).catch(() => undefined);
  }

  async listDrift(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const items = await this.prisma.complianceDriftEvent.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200,
    });
    return { items, total: items.length };
  }

  /** §139: a technical state change re-evaluates ONLY controls whose
   *  signal set intersects the changed signal keys. */
  async reevaluateForSignals(user: RequestUser, workspaceId: string, changedSignalKeys: string[]) {
    requireGrcPermission(user, "TEST_CONTROLS");
    await this.controls.ensureCatalog(user, workspaceId);
    const tests = await this.prisma.controlTest.findMany({ where: { workspaceId } });
    const affected = new Set<string>();
    for (const t of tests) {
      const keys = Array.isArray(t.signalKeys) ? (t.signalKeys as string[]) : [];
      if (keys.some((k) => changedSignalKeys.includes(k))) affected.add(t.controlId);
    }
    const results = [];
    for (const controlId of affected) {
      results.push(await this.evaluate(user, workspaceId, controlId));
    }
    return { reevaluated: results.length, controlIds: [...affected] };
  }

  /* ------------------------------ schedules ------------------------------ */

  async createSchedule(user: RequestUser, workspaceId: string, controlId: string, cron: string) {
    requireGrcPermission(user, "TEST_CONTROLS");
    await this.controls.findControl(workspaceId, controlId);
    // §105: schedules trigger read-only re-evaluation only — the
    // schedule stores no command and cannot start scans.
    const row = await this.prisma.controlTestSchedule.create({
      data: { workspaceId, controlId, cron, enabled: true },
    });
    return row;
  }

  async listSchedules(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const items = await this.prisma.controlTestSchedule.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    return { items, total: items.length };
  }

  async getEvaluation(user: RequestUser, workspaceId: string, controlId: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const control = await this.prisma.securityControl.findFirst({ where: { id: controlId, workspaceId } });
    if (!control) throw new NotFoundException("Control not found in this workspace");
    const latest = await this.prisma.controlEvaluation.findFirst({
      where: { workspaceId, controlId }, orderBy: { evaluatedAt: "desc" },
    });
    return { control, latestEvaluation: latest };
  }
}
