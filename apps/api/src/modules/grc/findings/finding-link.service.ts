import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { suggestControlForFinding } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import { ControlService } from "../controls/control.service";
import type { OverrideFindingLinkInput } from "../dto/schemas";

/**
 * Finding ↔ control linkage (Prompt 26 §84–§87). A technical control
 * failure LINKS to the canonical finding where one semantically
 * exists — it never duplicates the vulnerability (§84). Automatic
 * suggestions carry a confidence (§86); analyst overrides replace
 * them and both transitions are in the audit history (§87).
 */
@Injectable()
export class FindingLinkService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly controls: ControlService,
  ) {}

  /** Domain bucket derived from the finding's scan/profile context. */
  private domainOf(finding: Record<string, unknown>): string | null {
    const sources = (finding.sources as string[]) ?? [];
    if (sources.some((s) => /trivy|grype/i.test(s))) return "CONTAINER";
    if (sources.some((s) => /prowler|scoutsuite/i.test(s))) return "CLOUD";
    if (sources.some((s) => /schemathesis|inql/i.test(s))) return "API";
    if (sources.some((s) => /nmap|masscan|naabu/i.test(s))) return "NETWORK";
    if (sources.some((s) => /kubescape|kube-bench/i.test(s))) return "KUBERNETES";
    return null;
  }

  async suggestForFinding(user: RequestUser, workspaceId: string, findingId: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) throw new NotFoundException("Finding not found in this workspace");
    const suggestion = suggestControlForFinding({
      cweId: finding.cwe, category: finding.vulnClass,
      securityDomain: this.domainOf(finding as Record<string, unknown>), title: finding.title,
    });
    return { findingId, suggestion };
  }

  async linkFinding(user: RequestUser, workspaceId: string, findingId: string) {
    requireGrcPermission(user, "MANAGE_CONTROLS");
    await this.controls.ensureCatalog(user, workspaceId);
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) throw new NotFoundException("Finding not found in this workspace");
    const existing = await this.prisma.findingControlLink.findFirst({ where: { workspaceId, findingId } });
    if (existing) return existing;
    const suggestion = suggestControlForFinding({
      cweId: finding.cwe, category: finding.vulnClass,
      securityDomain: this.domainOf(finding as Record<string, unknown>), title: finding.title,
    });
    if (!suggestion) throw new BadRequestException("No deterministic control mapping rule matches this finding (§85)");
    const control = await this.prisma.securityControl.findFirst({ where: { workspaceId, code: suggestion.controlCode } });
    if (!control) throw new BadRequestException(`Mapped control ${suggestion.controlCode} is not in the workspace library`);
    const row = await this.prisma.findingControlLink.create({
      data: {
        workspaceId, findingId, controlId: control.id, confidence: suggestion.confidence,
        origin: "AUTOMATIC", ruleId: suggestion.ruleId, rationale: suggestion.rationale, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_UPDATED", resourceType: "FindingControlLink", resourceId: row.id,
      metadata: { findingId, controlCode: suggestion.controlCode, confidence: suggestion.confidence },
    });
    return row;
  }

  /** §87: analyst override — the automatic link is replaced, and the
   *  replacement is itself audited (history is never rewritten). */
  async overrideLink(user: RequestUser, workspaceId: string, findingId: string, input: OverrideFindingLinkInput) {
    requireGrcPermission(user, "MANAGE_CONTROLS");
    const control = await this.controls.findControl(workspaceId, input.controlId);
    const existing = await this.prisma.findingControlLink.findFirst({ where: { workspaceId, findingId } });
    const row = existing
      ? await this.prisma.findingControlLink.update({
          where: { id: existing.id },
          data: { controlId: control.id, origin: "ANALYST_OVERRIDE", confidence: "HIGH", ruleId: null, rationale: input.rationale ?? "Analyst override", createdBy: user.id },
        })
      : await this.prisma.findingControlLink.create({
          data: {
            workspaceId, findingId, controlId: control.id, confidence: "HIGH",
            origin: "ANALYST_OVERRIDE", rationale: input.rationale ?? "Analyst override", createdBy: user.id,
          },
        });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_UPDATED", resourceType: "FindingControlLink", resourceId: row.id,
      metadata: { findingId, override: true, previousControlId: existing?.controlId ?? null, controlId: control.id },
    });
    return row;
  }

  async listLinks(user: RequestUser, workspaceId: string, controlId?: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const items = await this.prisma.findingControlLink.findMany({
      where: { workspaceId, ...(controlId ? { controlId } : {}) }, orderBy: { createdAt: "desc" }, take: 500,
    });
    return { items, total: items.length };
  }
}
