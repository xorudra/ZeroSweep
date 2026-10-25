import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { FRAMEWORK_CATALOG, GRC_DISCLAIMER } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import type { ImportFrameworkInput } from "../dto/schemas";

/**
 * Framework registry (Prompt 26 §3–§6). Framework versions are
 * IMMUTABLE once published (§4): importing a (key, version) that
 * already exists as ACTIVE/DEPRECATED/RETIRED is refused; a new
 * edition arrives as a new version row and never rewrites history.
 */
@Injectable()
export class FrameworkService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async listFrameworks(user: RequestUser) {
    requireGrcPermission(user, "VIEW_GRC");
    const rows = await this.prisma.complianceFramework.findMany({
      orderBy: [{ key: "asc" }, { version: "asc" }],
    });
    const items = [];
    for (const fw of rows) {
      const requirementCount = await this.prisma.complianceRequirement.count({ where: { frameworkId: fw.id } });
      items.push({ ...fw, requirementCount });
    }
    return { items, disclaimer: GRC_DISCLAIMER };
  }

  async getFramework(user: RequestUser, id: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const framework = await this.prisma.complianceFramework.findFirst({ where: { id } });
    if (!framework) throw new NotFoundException("Framework not found");
    const requirements = await this.prisma.complianceRequirement.findMany({
      where: { frameworkId: id }, orderBy: [{ level: "asc" }, { requirementId: "asc" }],
    });
    return { ...framework, requirements, disclaimer: GRC_DISCLAIMER };
  }

  /** The framework catalog is GLOBAL (no workspaceId) and consumed by
   *  every tenant: writes are platform-operator operations. A tenant
   *  OWNER/ADMIN role never suffices — the deployment platform-admin
   *  flag is required, exactly like the platform-ops plane (§98). */
  private requirePlatformAdmin(user: RequestUser) {
    if (user.isPlatformAdmin !== true) {
      throw new ForbiddenException("Shared framework catalog writes require a platform administrator; organization roles do not grant catalog access.");
    }
  }

  /** Import a versioned framework (catalog key or synthetic fixture, §121). */
  async importFramework(user: RequestUser, workspaceId: string, input: ImportFrameworkInput) {
    requireGrcPermission(user, "MANAGE_FRAMEWORKS");
    this.requirePlatformAdmin(user);
    const existing = await this.prisma.complianceFramework.findFirst({
      where: { key: input.key, version: input.version },
    });
    if (existing) {
      throw new ConflictException(
        `Framework ${input.key} version ${input.version} already exists (status ${existing.status}); published versions are immutable (§4) — import a new version instead.`,
      );
    }
    const framework = await this.prisma.complianceFramework.create({
      data: {
        key: input.key, name: input.name, publisher: input.publisher ?? "", version: input.version,
        description: `${input.name} ${input.version} — reference catalog; ZeroSweep assessments are evidence, never a certification.`,
        status: "ACTIVE",
        effectiveDate: input.effectiveDate ? new Date(input.effectiveDate) : null,
        metadata: { source: "IMPORT" },
      },
    });
    // Hierarchy validation (§6/§121): every parent must be in the payload.
    const ids = new Set(input.requirements.map((r) => r.requirementId));
    for (const r of input.requirements) {
      if (r.parentRequirementId && !ids.has(r.parentRequirementId)) {
        throw new BadRequestException(`Requirement ${r.requirementId} references unknown parent ${r.parentRequirementId}`);
      }
    }
    for (const r of input.requirements) {
      await this.prisma.complianceRequirement.create({
        data: {
          frameworkId: framework.id, requirementId: r.requirementId,
          parentRequirementId: r.parentRequirementId ?? null, title: r.title,
          description: r.description ?? "", category: r.category ?? "", level: r.level ?? 1,
        },
      });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "FRAMEWORK_IMPORTED", resourceType: "ComplianceFramework", resourceId: framework.id,
      metadata: { key: input.key, version: input.version, requirements: input.requirements.length },
    });
    return this.getFramework(user, framework.id);
  }

  /** Import one of the shipped catalog versions (§3). */
  async importCatalogFramework(user: RequestUser, workspaceId: string, key: string) {
    const data = FRAMEWORK_CATALOG.find((f) => f.key === key);
    if (!data) throw new NotFoundException(`No catalog framework with key ${key}`);
    return this.importFramework(user, workspaceId, {
      key: data.key, name: data.name, publisher: data.publisher, version: data.version,
      effectiveDate: new Date(data.effectiveDate).toISOString(),
      requirements: data.requirements,
    });
  }

  async setFrameworkStatus(user: RequestUser, workspaceId: string, id: string, status: string) {
    requireGrcPermission(user, "MANAGE_FRAMEWORKS");
    this.requirePlatformAdmin(user);
    if (!["DRAFT", "ACTIVE", "DEPRECATED", "RETIRED"].includes(status)) {
      throw new BadRequestException(`Unknown framework status ${status} (§5)`);
    }
    const framework = await this.prisma.complianceFramework.findFirst({ where: { id } });
    if (!framework) throw new NotFoundException("Framework not found");
    const updated = await this.prisma.complianceFramework.update({
      where: { id },
      data: { status, retiredDate: status === "RETIRED" ? new Date() : framework.retiredDate },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "FRAMEWORK_IMPORTED", resourceType: "ComplianceFramework", resourceId: id,
      metadata: { statusChange: status },
    });
    return updated;
  }
}
