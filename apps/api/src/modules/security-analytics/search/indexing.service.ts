import { Inject, Injectable } from "@nestjs/common";
import { buildSearchableText, redactDisplayText } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { deriveExposure } from "../../continuous-security/snapshots/snapshot.service";

export const SEARCH_DOCUMENT_TYPES = [
  "ASSET", "FINDING", "SCAN", "REPORT", "REPOSITORY", "CONTROL", "RISK", "AUDIT", "TICKET", "SECURITY_EVENT",
] as const;

interface DocDraft {
  documentType: string; resourceId: string; title: string; summary: string;
  textParts: Array<string | null | undefined>;
  facets: Record<string, unknown>; classification: string;
  riskScore?: number | null; severity?: string | null; updatedAt?: Date;
}

/**
 * Search indexing (Prompt 27 §19–§22, §111–§112, §115–§116).
 *
 * Documents are built ONLY from tenant-scoped operational records,
 * and every text field passes the platform redaction pipeline before
 * it can reach the index (§112) — a secret in source evidence is
 * absent from searchableText (§130). Reindexing rebuilds through
 * this same path, so tenant boundaries, classification and
 * redaction are preserved by construction (§116).
 */
@Injectable()
export class IndexingService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async indexWorkspace(scope: { organizationId: string; workspaceId: string }, documentType?: string): Promise<{ indexed: number; byType: Record<string, number> }> {
    const drafts: DocDraft[] = [];
    const want = (t: string) => !documentType || documentType === t;
    const ws = scope.workspaceId;

    if (want("ASSET")) {
      const assets = await this.prisma.asset.findMany({ where: { workspaceId: ws }, take: 5000 });
      const techs = await this.prisma.technology.findMany({ take: 20_000 });
      const techByAsset = new Map<string, string[]>();
      for (const t of techs) {
        techByAsset.set(t.assetId, [...(techByAsset.get(t.assetId) ?? []), t.name]);
      }
      for (const a of assets) {
        const techNames = techByAsset.get(a.id) ?? [];
        drafts.push({
          documentType: "ASSET", resourceId: a.id, title: a.host,
          summary: `${a.type} · criticality ${a.criticality} · exposure ${deriveExposure(a.ip)}`,
          textParts: [a.host, a.ip, a.type, a.network, a.osHint, ...techNames],
          facets: {
            assetType: a.type, criticality: a.criticality, scopeStatus: a.scopeStatus,
            internetExposed: deriveExposure(a.ip) === "INTERNET_FACING", technologies: techNames, assetHost: a.host,
          },
          classification: "INTERNAL", updatedAt: a.updatedAt,
        });
      }
    }

    if (want("FINDING")) {
      const findings = await this.prisma.finding.findMany({ where: { workspaceId: ws }, take: 10_000 });
      const repoNames = new Map<string, string>();
      if (findings.some((f) => f.repositoryId)) {
        const repos = await this.prisma.sourceRepository.findMany({ where: { workspaceId: ws }, take: 1000 });
        for (const r of repos) repoNames.set(r.id, r.name);
      }
      for (const f of findings) {
        drafts.push({
          documentType: "FINDING", resourceId: f.id, title: f.title,
          summary: `${f.severity} · ${f.lifecycleStatus} · ${f.cve ?? f.cwe ?? f.sourceDomain ?? ""}`,
          textParts: [f.title, f.description, f.remediation, f.cve, f.cwe, f.host, f.endpoint, f.vulnClass],
          facets: {
            severity: f.severity, status: f.status, lifecycleStatus: f.lifecycleStatus,
            cve: f.cve, cwe: f.cwe, kev: f.kevListed, verified: f.verificationStatus === "CONFIRMED",
            source: f.sourceDomain, priority: f.priority, repository: f.repositoryId ? (repoNames.get(f.repositoryId) ?? null) : null,
            internetExposed: f.host ? undefined : undefined, assetHost: f.host,
          },
          classification: f.dataSensitivity ?? "INTERNAL",
          riskScore: f.riskScore, severity: f.severity, updatedAt: f.updatedAt,
        });
      }
    }

    if (want("SCAN")) {
      const scans = await this.prisma.scan.findMany({ where: { workspaceId: ws }, take: 5000 });
      for (const s of scans) {
        drafts.push({
          documentType: "SCAN", resourceId: s.id, title: `Scan ${s.id.slice(0, 8)} — ${s.status}`,
          summary: `status ${s.status}`, textParts: [s.id, s.status, s.errorSummary],
          facets: { status: s.status }, classification: "INTERNAL", updatedAt: s.updatedAt,
        });
      }
    }

    if (want("REPORT")) {
      const reports = await this.prisma.securityReport.findMany({ where: { workspaceId: ws }, take: 2000 });
      for (const r of reports) {
        drafts.push({
          documentType: "REPORT", resourceId: r.id, title: r.title,
          summary: `${r.type} · ${r.status}`, textParts: [r.title, r.type, r.status],
          facets: { status: r.status, type: r.type }, classification: r.classification ?? "CONFIDENTIAL", updatedAt: r.updatedAt,
        });
      }
    }

    if (want("REPOSITORY")) {
      const repos = await this.prisma.sourceRepository.findMany({ where: { workspaceId: ws }, take: 2000 });
      for (const r of repos) {
        drafts.push({
          documentType: "REPOSITORY", resourceId: r.id, title: r.name,
          summary: `${r.provider ?? "repository"} · ${r.visibility}`,
          textParts: [r.name, r.provider, r.defaultBranch],
          facets: { visibility: r.visibility, source: r.sourceKind, repository: r.name },
          classification: "INTERNAL", updatedAt: r.updatedAt,
        });
      }
    }

    if (want("CONTROL")) {
      const controls = await this.prisma.securityControl.findMany({ where: { workspaceId: ws }, take: 5000 });
      for (const c of controls) {
        drafts.push({
          documentType: "CONTROL", resourceId: c.id, title: `${c.code} — ${c.title}`,
          summary: `${c.controlType} · ${c.implementationStatus}`,
          textParts: [c.code, c.title, c.description],
          facets: { control: c.code, status: c.implementationStatus },
          classification: "INTERNAL", updatedAt: c.updatedAt,
        });
      }
    }

    if (want("RISK")) {
      const risks = await this.prisma.riskRecord.findMany({ where: { workspaceId: ws }, take: 5000 });
      for (const r of risks) {
        drafts.push({
          documentType: "RISK", resourceId: r.id, title: r.title,
          summary: `${r.category} · inherent ${r.inherentBand} · ${r.status}`,
          textParts: [r.title, r.description, r.category, r.source],
          facets: { status: r.status, severity: r.inherentBand, source: r.source },
          classification: "CONFIDENTIAL", riskScore: r.inherentScore * 20, updatedAt: r.updatedAt,
        });
      }
    }

    if (want("AUDIT")) {
      const logs = await this.prisma.auditLog.findMany({
        where: { workspaceId: ws }, orderBy: { createdAt: "desc" }, take: 2000,
      });
      for (const l of logs) {
        drafts.push({
          documentType: "AUDIT", resourceId: l.id, title: `${l.action} — ${l.resourceType}`,
          summary: `audit event ${l.action}`, textParts: [l.action, l.resourceType, l.resourceId],
          facets: { status: l.action, source: "AUDIT" }, classification: "CONFIDENTIAL", updatedAt: l.createdAt,
        });
      }
    }

    if (want("TICKET")) {
      const tickets = await this.prisma.remediationTicket.findMany({ where: { workspaceId: ws }, take: 5000 });
      for (const t of tickets) {
        drafts.push({
          documentType: "TICKET", resourceId: t.id, title: t.externalKey ?? `Ticket ${t.id.slice(0, 8)}`,
          summary: `${t.status} · sync ${t.syncState}`, textParts: [t.externalKey, t.status, t.externalId],
          facets: { status: t.status }, classification: "INTERNAL", updatedAt: t.updatedAt,
        });
      }
    }

    if (want("SECURITY_EVENT")) {
      const events = await this.prisma.securityAnalyticsEvent.findMany({
        where: { workspaceId: ws }, orderBy: { eventTime: "desc" }, take: 5000,
      });
      for (const e of events) {
        drafts.push({
          documentType: "SECURITY_EVENT", resourceId: e.id, title: `${e.eventType} — ${e.resourceType}`,
          summary: `${e.eventType} at ${e.eventTime.toISOString()}`,
          textParts: [e.eventType, e.resourceType, e.resourceId, e.severity],
          facets: { eventType: e.eventType, severity: e.severity, status: e.eventType },
          classification: e.classification, riskScore: e.riskScore, severity: e.severity, updatedAt: e.eventTime,
        });
      }
    }

    const byType: Record<string, number> = {};
    for (const draft of drafts) {
      await this.upsertDocument(scope, draft);
      byType[draft.documentType] = (byType[draft.documentType] ?? 0) + 1;
    }
    return { indexed: drafts.length, byType };
  }

  private async upsertDocument(scope: { organizationId: string; workspaceId: string }, draft: DocDraft): Promise<void> {
    const data = {
      organizationId: scope.organizationId, workspaceId: scope.workspaceId,
      documentType: draft.documentType, resourceId: draft.resourceId,
      title: redactDisplayText(draft.title), summary: redactDisplayText(draft.summary),
      searchableText: buildSearchableText(draft.textParts),
      facets: draft.facets as never, classification: draft.classification,
      riskScore: draft.riskScore ?? null, severity: draft.severity ?? null,
    };
    const existing = await this.prisma.securitySearchDocument.findFirst({
      where: { workspaceId: scope.workspaceId, documentType: draft.documentType, resourceId: draft.resourceId },
    });
    if (existing) await this.prisma.securitySearchDocument.update({ where: { id: existing.id }, data });
    else await this.prisma.securitySearchDocument.create({ data });
  }
}
