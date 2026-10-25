import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  BUILTIN_CORRELATION_RULES, evaluateCorrelation, type CorrelationRuleDef, type CorrelationSubject,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { deriveExposure } from "../../continuous-security/snapshots/snapshot.service";

/**
 * Cross-domain correlation (Prompt 27 §73–§80).
 *
 * Subjects are joined views (finding + asset + repository + control)
 * assembled from tenant-scoped operational records. Rules — built-in
 * or workspace-defined — are typed declarative conditions evaluated
 * by the SDK engine; a rule can never carry code (§75/§148).
 * Signals dedupe by stable fingerprint (§78): a repeated match
 * updates lastSeenAt/occurrenceCount on the SAME row, and a signal
 * whose evidence disappears is resolved by the engine — never by
 * overwriting canonical finding severity (§80).
 */
@Injectable()
export class CorrelationService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async runCorrelations(workspaceId: string): Promise<{ evaluated: number; created: number; updated: number; resolved: number }> {
    const [findings, assets, repos, rules] = await Promise.all([
      this.prisma.finding.findMany({ where: { workspaceId }, take: 10_000 }),
      this.prisma.asset.findMany({ where: { workspaceId }, take: 10_000 }),
      this.prisma.sourceRepository.findMany({ where: { workspaceId }, take: 2000 }),
      this.workspaceRules(workspaceId),
    ]);
    const assetById = new Map(assets.map((a) => [a.id, a]));
    const repoById = new Map(repos.map((r) => [r.id, r]));
    const seenFingerprints = new Set<string>();
    let created = 0; let updated = 0; let evaluated = 0;

    const upsertMatches = async (subject: CorrelationSubject) => {
      evaluated++;
      for (const match of evaluateCorrelation(subject, workspaceId, rules)) {
        seenFingerprints.add(match.fingerprint);
        const existing = await this.prisma.securityCorrelationSignal.findFirst({
          where: { workspaceId, fingerprint: match.fingerprint },
        });
        const evidence = match.evidence as never;
        if (existing) {
          await this.prisma.securityCorrelationSignal.update({
            where: { id: existing.id },
            data: {
              lastSeenAt: new Date(), occurrenceCount: (existing.occurrenceCount ?? 1) + 1,
              confidence: match.confidence, severity: match.rule.severity, evidence,
              status: existing.status === "RESOLVED" ? "OPEN" : existing.status,
            },
          });
          updated++;
        } else {
          await this.prisma.securityCorrelationSignal.create({
            data: {
              workspaceId, signalType: match.rule.outputType, fingerprint: match.fingerprint,
              severity: match.rule.severity, confidence: match.confidence,
              assetId: subject.assetId ?? null, findingId: subject.findingId ?? null,
              resourceType: subject.resourceType ?? null, resourceId: subject.resourceId ?? null,
              evidence, status: "OPEN", occurrenceCount: 1, firstSeenAt: new Date(), lastSeenAt: new Date(),
            },
          });
          created++;
        }
      }
    };

    for (const f of findings) {
      const asset = f.assetId ? assetById.get(f.assetId) : undefined;
      const repo = f.repositoryId ? repoById.get(f.repositoryId) : undefined;
      await upsertMatches({
        findingId: f.id, assetId: f.assetId ?? null, resourceType: "FINDING", resourceId: f.id,
        findingSeverity: f.severity, findingStatus: f.status, lifecycleStatus: f.lifecycleStatus,
        verificationStatus: f.verificationStatus, kevListed: f.kevListed, epssScore: f.epssScore,
        riskScore: f.riskScore, category: f.category, sourceDomain: f.sourceDomain,
        cve: f.cve, cwe: f.cwe,
        assetCriticality: asset?.criticality ?? null,
        internetExposed: asset ? deriveExposure(asset.ip) === "INTERNET_FACING" : undefined,
        repositoryVisibility: repo?.visibility ?? null,
        workloadPublic: f.clusterRef ? (asset ? deriveExposure(asset.ip) === "INTERNET_FACING" : undefined) : undefined,
      });
    }

    // Control-failure subjects (§76 FAILED_CONTROL_WITH_ACTIVE_CRITICAL_FINDING).
    const evaluations = await this.prisma.controlEvaluation.findMany({
      where: { workspaceId }, orderBy: { evaluatedAt: "desc" }, take: 2000,
    });
    const latestByControl = new Map<string, string>();
    for (const e of evaluations) if (!latestByControl.has(e.controlId)) latestByControl.set(e.controlId, e.result);
    const criticalOpen = findings.find((f) => f.severity === "CRITICAL" && !["RESOLVED", "REMEDIATED", "CLOSED", "FALSE_POSITIVE"].includes(f.lifecycleStatus));
    for (const [controlId, result] of latestByControl) {
      if (result !== "FAIL" || !criticalOpen) continue;
      await upsertMatches({
        resourceType: "CONTROL", resourceId: controlId, controlState: "FAIL",
        findingId: criticalOpen.id, findingSeverity: "CRITICAL",
        verificationStatus: criticalOpen.verificationStatus,
      });
    }

    // Resolve open signals whose evidence no longer matches (§79 lifecycle).
    const open = await this.prisma.securityCorrelationSignal.findMany({
      where: { workspaceId, status: "OPEN" }, take: 5000,
    });
    let resolved = 0;
    for (const signal of open) {
      if (!seenFingerprints.has(signal.fingerprint)) {
        await this.prisma.securityCorrelationSignal.update({ where: { id: signal.id }, data: { status: "RESOLVED" } });
        resolved++;
      }
    }
    return { evaluated, created, updated, resolved };
  }

  private async workspaceRules(workspaceId: string): Promise<CorrelationRuleDef[]> {
    const rows = await this.prisma.correlationRule.findMany({
      where: { enabled: true } as never, take: 200,
    });
    const custom = (rows as unknown as Array<{ workspaceId: string | null; name: string; description: string; inputTypes: unknown; conditions: unknown; severity: string; outputType: string; version: number }>)
      .filter((r) => r.workspaceId === null || r.workspaceId === workspaceId)
      .map((r) => ({
        name: r.name, description: r.description, inputTypes: (r.inputTypes as string[]) ?? [],
        conditions: (r.conditions as CorrelationRuleDef["conditions"]) ?? [],
        severity: r.severity, outputType: r.outputType, version: r.version,
      }));
    return [...BUILTIN_CORRELATION_RULES, ...custom];
  }

  async listSignals(workspaceId: string, status?: string) {
    const items = await this.prisma.securityCorrelationSignal.findMany({
      where: { workspaceId, ...(status ? { status } : {}) } as never,
      orderBy: { lastSeenAt: "desc" }, take: 500,
    });
    return { items, total: items.length };
  }

  async getSignal(workspaceId: string, id: string) {
    const signal = await this.prisma.securityCorrelationSignal.findFirst({ where: { id, workspaceId } });
    if (!signal) throw new NotFoundException("Correlation signal not found");
    return signal;
  }

  async setSignalStatus(workspaceId: string, id: string, status: string) {
    const signal = await this.getSignal(workspaceId, id);
    return this.prisma.securityCorrelationSignal.update({ where: { id: signal.id }, data: { status } });
  }

  async createRule(workspaceId: string, body: { name: string; description?: string; conditions: CorrelationRuleDef["conditions"]; severity: string; outputType: string }) {
    // Conditions are validated as typed data — code-shaped values are rejected (§75).
    for (const c of body.conditions ?? []) {
      if (!c || typeof c.field !== "string" || !["eq", "neq", "gte", "lte", "in", "truthy", "falsy"].includes(c.op)) {
        throw new BadRequestException("Correlation conditions must be typed {field, op, value} entries — arbitrary expressions are not accepted (§75)");
      }
    }
    return this.prisma.correlationRule.create({
      data: {
        workspaceId, name: body.name, description: body.description ?? "",
        inputTypes: ["FINDING"] as never, conditions: (body.conditions ?? []) as never,
        severity: body.severity, outputType: body.outputType,
      },
    });
  }
}
