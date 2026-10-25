import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  correlateFindings, fingerprintOfFinding, parseGreenboneReport, parseNessusReport,
  type ParsedScannerReport,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireVmPermission } from "./permissions";

/**
 * Scanner report import (Prompt 11 §74–§76): preview first — counts,
 * scope mismatches, duplicates and warnings are shown BEFORE anything is
 * stored; out-of-scope content is rejected or quarantined, never silently
 * imported. Reports are hostile input: parsers enforce size caps, XXE /
 * DOCTYPE rejection and field sanitization (§76). Hostile payloads are
 * never stored — commit re-submits the report and its checksum must
 * match the recorded preview.
 */
@Injectable()
export class ScannerImportsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private parse(scanner: string, raw: string): ParsedScannerReport {
    if (scanner === "nessus-professional") return parseNessusReport(raw);
    if (scanner === "greenbone-openvas") return parseGreenboneReport(raw);
    throw new BadRequestException(`scanner ${scanner} does not support report import in this module (use the Prompt 8 import flows for proxy scanners)`);
  }

  /** Hosts a report claims vs the workspace's in-scope assets (§75). */
  private async scopeVerdicts(workspaceId: string, hosts: string[]) {
    const assets = await this.prisma.asset.findMany({
      where: { workspaceId, host: { in: hosts } },
      select: { host: true, scopeStatus: true },
    });
    const byHost = new Map(assets.map((a) => [a.host, a.scopeStatus]));
    return hosts.map((host) => ({
      host,
      verdict: !byHost.has(host) ? "UNKNOWN_ASSET" as const
        : byHost.get(host) === "IN_SCOPE" ? "IN_SCOPE" as const : "OUT_OF_SCOPE" as const,
    }));
  }

  async preview(user: RequestUser, workspaceId: string, input: { scanner: string; raw: string }) {
    requireVmPermission(user, "MANAGE_SCANNERS");
    let report: ParsedScannerReport;
    try {
      report = this.parse(input.scanner, input.raw);
    } catch (err) {
      // A rejected hostile/invalid report is itself recorded (§76).
      const rejected = await this.prisma.scannerReportImport.create({
        data: {
          workspaceId, scanner: input.scanner, createdBy: user.id, status: "REJECTED",
          checksum: "",
          summary: { error: err instanceof Error ? err.message : "parse failure" } as never,
        },
      });
      throw new BadRequestException(`report rejected: ${err instanceof Error ? err.message : "parse failure"} (import ${rejected.id})`);
    }
    const verdicts = await this.scopeVerdicts(workspaceId, report.hosts);
    const inScopeHosts = new Set(verdicts.filter((v) => v.verdict === "IN_SCOPE").map((v) => v.host));
    const importable = report.findings.filter((f) => f.host && inScopeHosts.has(f.host));
    const existing = await this.prisma.finding.findMany({
      where: { workspaceId, fingerprint: { in: importable.map((f) => fingerprintOfFinding(f)) } },
      select: { fingerprint: true },
    });
    const existingSet = new Set(existing.map((e) => e.fingerprint));
    const { stats } = correlateFindings(importable);
    const scopeMismatches = verdicts.filter((v) => v.verdict !== "IN_SCOPE");
    const summary = {
      totalFindings: report.findings.length,
      importableFindings: importable.length,
      duplicatesWithinReport: stats.duplicatesMerged,
      alreadyKnown: importable.filter((f) => existingSet.has(fingerprintOfFinding(f))).length,
      scopeMismatches: verdicts,
      warnings: [...report.warnings, ...(scopeMismatches.length ? [`${scopeMismatches.length} host(s) are not in-scope assets — their findings will be quarantined, not imported`] : [])],
      decision: scopeMismatches.length === verdicts.length && verdicts.length > 0 ? "REJECT" : scopeMismatches.length > 0 ? "QUARANTINE_PARTIAL" : "IMPORT",
    };
    const row = await this.prisma.scannerReportImport.create({
      data: {
        workspaceId, scanner: input.scanner, createdBy: user.id,
        status: summary.decision === "REJECT" ? "REJECTED" : "PREVIEW",
        checksum: report.checksum,
        warnings: summary.warnings as never,
        summary: { ...summary, importedCount: 0 } as never,
      },
    });
    return { importId: row.id, checksum: report.checksum, ...summary };
  }

  /**
   * Commit a previewed import. The report is re-parsed and its checksum
   * must match the preview record; in-scope findings are persisted
   * through the SAME correlation pipeline as live scans; out-of-scope
   * findings are counted as quarantined and never stored (§75).
   */
  async commit(user: RequestUser, workspaceId: string, importId: string, raw: string, scanId: string) {
    requireVmPermission(user, "MANAGE_SCANNERS");
    const row = await this.prisma.scannerReportImport.findFirst({ where: { id: importId, workspaceId } });
    if (!row) throw new NotFoundException("import preview not found in this workspace");
    if (row.status !== "PREVIEW") throw new BadRequestException(`import is ${row.status} — only PREVIEW imports can be committed`);
    // Findings belong to a scan in this schema (Phase 8 precedent): the
    // import attaches to an existing scan of this workspace.
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId } });
    if (!scan) throw new BadRequestException("scanId must reference a scan in this workspace — imported findings attach to a scan");
    const report = this.parse(row.scanner, raw);
    if (report.checksum !== row.checksum) throw new BadRequestException("report checksum does not match the previewed report — re-preview the exact file");
    const verdicts = await this.scopeVerdicts(workspaceId, report.hosts);
    const inScopeHosts = new Set(verdicts.filter((v) => v.verdict === "IN_SCOPE").map((v) => v.host));
    const importable = report.findings.filter((f) => f.host && inScopeHosts.has(f.host));
    const quarantined = report.findings.length - importable.length;
    const { findings: correlated } = correlateFindings(importable);
    let imported = 0;
    let duplicates = 0;
    for (const c of correlated) {
      const f = c.finding;
      const asset = await this.prisma.asset.findFirst({ where: { workspaceId, host: f.host ?? "" } });
      const existing = await this.prisma.finding.findFirst({ where: { workspaceId, fingerprint: c.canonicalFingerprint } });
      if (existing) {
        duplicates++;
        // Corroboration: record an observation; never a second canonical (§62/§63).
        for (const source of c.sources) {
          await this.prisma.findingObservation.upsert({
            where: { findingId_sourceTool_sourceFingerprint: { findingId: existing.id, sourceTool: source.tool, sourceFingerprint: source.sourceFingerprint } },
            create: {
              findingId: existing.id, workspaceId, scanId, sourceTool: source.tool, sourceFingerprint: source.sourceFingerprint,
              severity: f.severity, summary: source.summary,
            },
            update: { observedAt: new Date(), severity: f.severity },
          });
        }
        await this.prisma.finding.update({ where: { id: existing.id }, data: { lastSeen: new Date(), sources: [...new Set([...existing.sources, ...c.sources.map((s) => s.tool)])] } });
        continue;
      }
      const created = await this.prisma.finding.create({
        data: {
          workspaceId, assetId: asset?.id, scanId,
          fingerprint: c.canonicalFingerprint, title: f.title, description: f.description,
          severity: f.severity, status: "OPEN", verificationStatus: c.verificationStatus,
          confidence: c.confidenceScore, confidenceBand: c.confidenceBand,
          host: f.host, port: f.port, endpoint: f.endpoint, cve: f.cve, cwe: f.cwe,
          vulnClass: f.vulnClass, owaspCategory: f.owaspCategory,
          cvssScore: f.cvssScore, cvssVector: f.cvssVector, remediation: f.remediation,
          sources: c.sources.map((s) => s.tool), riskScore: c.riskScore, riskBand: c.riskBand,
          riskExplanation: c.riskExplanation as never, isMock: false,
          references: { create: f.referencesDetailed.map((r) => ({ type: r.type, label: r.label, url: r.url })) },
          history: { create: { workspaceId, event: "CREATED", metadata: { importId, scanner: row.scanner } as never } },
        } as never,
      });
      for (const source of c.sources) {
        await this.prisma.findingObservation.create({
          data: {
            findingId: created.id, workspaceId, scanId, sourceTool: source.tool, sourceFingerprint: source.sourceFingerprint,
            severity: f.severity, summary: source.summary,
          },
        });
      }
      imported++;
    }
    const done = await this.prisma.scannerReportImport.update({
      where: { id: importId },
      data: {
        status: quarantined > 0 ? "QUARANTINED" : "COMMITTED", scanId,
        summary: { ...((row.summary as Record<string, unknown>) ?? {}), importedCount: imported, duplicateCount: duplicates, scopeMismatchCount: quarantined } as never,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SCANNER_REPORT_IMPORTED", resourceType: "SCANNER_IMPORT", resourceId: importId,
      metadata: { scanner: row.scanner, imported, duplicates, quarantined, checksum: report.checksum },
    });
    return { import: done, imported, duplicates, quarantined };
  }

  async list(workspaceId: string) {
    return this.prisma.scannerReportImport.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
  }
}
