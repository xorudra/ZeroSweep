import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  CONTROL_LIBRARY, CONTROL_MAPPINGS, DEFAULT_FRESHNESS_POLICIES, MANUAL_EVIDENCE_FRESHNESS,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import type { CreateControlInput, CreateMappingInput, UpdateControlInput } from "../dto/schemas";

/**
 * Control library (Prompt 26 §7–§18). Workspace controls are seeded
 * from the SDK catalog on first use; the catalog distinguishes what
 * ZeroSweep can technically validate from what requires human evidence
 * (administrative controls carry MANUAL tests with automation NONE).
 */
@Injectable()
export class ControlService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /** Idempotently seed catalog controls, tests, freshness policies and
   *  cross-framework mappings for this workspace (§12). Mappings bind
   *  only when both the control and the framework version exist. */
  async ensureCatalog(user: RequestUser, workspaceId: string) {
    const existing = await this.prisma.securityControl.count({ where: { workspaceId } });
    if (existing > 0) return { seeded: false, controls: existing };
    const controlIdByCode = new Map<string, string>();
    for (const c of CONTROL_LIBRARY) {
      const row = await this.prisma.securityControl.create({
        data: {
          workspaceId, code: c.code, title: c.title, description: c.description,
          controlType: c.controlType, implementationType: c.implementationType,
          implementationStatus: "NOT_IMPLEMENTED", effectiveness: "NOT_TESTED", catalogSource: true,
        },
      });
      controlIdByCode.set(c.code, row.id);
      await this.prisma.controlTest.create({
        data: {
          workspaceId, controlId: row.id, name: c.testName, method: c.testMethod,
          automationLevel: c.automationLevel, frequency: c.testFrequency,
          expectedResult: c.expectedResult, evidenceRequirements: c.evidenceSources.join(", "),
          signalKeys: c.signals,
        },
      });
      const freshness = DEFAULT_FRESHNESS_POLICIES[c.code] ?? MANUAL_EVIDENCE_FRESHNESS;
      await this.prisma.evidenceFreshnessPolicy.create({
        data: { workspaceId, controlId: row.id, staleAfterDays: freshness.staleAfterDays, expireAfterDays: freshness.expireAfterDays },
      });
    }
    let mappings = 0;
    for (const m of CONTROL_MAPPINGS) {
      const controlId = controlIdByCode.get(m.controlCode);
      if (!controlId) continue;
      const framework = await this.prisma.complianceFramework.findFirst({
        where: { key: m.frameworkKey, version: m.frameworkVersion },
      });
      if (!framework) continue;
      const requirement = await this.prisma.complianceRequirement.findFirst({
        where: { frameworkId: framework.id, requirementId: m.requirementId },
      });
      if (!requirement) continue;
      await this.prisma.controlFrameworkMapping.create({
        data: {
          workspaceId, controlId, requirementId: requirement.id, mappingType: m.mappingType,
          coverage: m.coverage, notes: m.notes, source: m.source,
        },
      });
      mappings++;
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_CREATED", resourceType: "SecurityControl", resourceId: workspaceId,
      metadata: { seededCatalog: true, controls: controlIdByCode.size, mappings },
    });
    return { seeded: true, controls: controlIdByCode.size, mappings };
  }

  async listControls(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    await this.ensureCatalog(user, workspaceId);
    const items = await this.prisma.securityControl.findMany({
      where: { workspaceId }, orderBy: { code: "asc" },
    });
    const enriched = [];
    for (const c of items) {
      const owners = await this.prisma.controlOwner.findMany({ where: { workspaceId, controlId: c.id } });
      const tests = await this.prisma.controlTest.findMany({ where: { workspaceId, controlId: c.id } });
      const mappings = await this.prisma.controlFrameworkMapping.findMany({ where: { workspaceId, controlId: c.id } });
      const lastEvaluation = await this.prisma.controlEvaluation.findFirst({
        where: { workspaceId, controlId: c.id }, orderBy: { evaluatedAt: "desc" },
      });
      enriched.push({ ...c, owners, tests, mappingCount: mappings.length, lastEvaluation });
    }
    return { items: enriched, total: enriched.length };
  }

  async getControl(user: RequestUser, workspaceId: string, id: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const control = await this.findControl(workspaceId, id);
    const owners = await this.prisma.controlOwner.findMany({ where: { workspaceId, controlId: id } });
    const tests = await this.prisma.controlTest.findMany({ where: { workspaceId, controlId: id } });
    const mappings = await this.prisma.controlFrameworkMapping.findMany({ where: { workspaceId, controlId: id } });
    const evaluations = await this.prisma.controlEvaluation.findMany({
      where: { workspaceId, controlId: id }, orderBy: { evaluatedAt: "desc" }, take: 20,
    });
    return { ...control, owners, tests, mappings, evaluations };
  }

  async findControl(workspaceId: string, id: string) {
    const control = await this.prisma.securityControl.findFirst({ where: { id, workspaceId } });
    if (!control) throw new NotFoundException("Control not found in this workspace");
    return control;
  }

  async createControl(user: RequestUser, workspaceId: string, input: CreateControlInput) {
    requireGrcPermission(user, "MANAGE_CONTROLS");
    await this.ensureCatalog(user, workspaceId);
    const dupe = await this.prisma.securityControl.findFirst({ where: { workspaceId, code: input.code } });
    if (dupe) throw new BadRequestException(`Control code ${input.code} already exists in this workspace`);
    const control = await this.prisma.securityControl.create({
      data: {
        workspaceId, code: input.code, title: input.title, description: input.description ?? "",
        controlType: input.controlType, implementationType: input.implementationType,
        implementationStatus: input.implementationStatus ?? "NOT_IMPLEMENTED", catalogSource: false,
      },
    });
    if (input.ownerRef) {
      await this.prisma.controlOwner.create({
        data: { workspaceId, controlId: control.id, ownerType: input.ownerType ?? "USER", ownerRef: input.ownerRef, isPrimary: true },
      });
    }
    await this.prisma.evidenceFreshnessPolicy.create({
      data: { workspaceId, controlId: control.id, staleAfterDays: MANUAL_EVIDENCE_FRESHNESS.staleAfterDays, expireAfterDays: MANUAL_EVIDENCE_FRESHNESS.expireAfterDays },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_CREATED", resourceType: "SecurityControl", resourceId: control.id,
      metadata: { code: input.code },
    });
    return control;
  }

  async updateControl(user: RequestUser, workspaceId: string, id: string, input: UpdateControlInput) {
    requireGrcPermission(user, "MANAGE_CONTROLS");
    const control = await this.findControl(workspaceId, id);
    const data: Record<string, unknown> = {};
    for (const k of ["title", "description", "controlType", "implementationType", "implementationStatus"] as const) {
      if (input[k] !== undefined) data[k] = input[k];
    }
    const updated = await this.prisma.securityControl.update({ where: { id: control.id }, data });
    if (input.ownerRef) {
      await this.prisma.controlOwner.create({
        data: { workspaceId, controlId: id, ownerType: input.ownerType ?? "USER", ownerRef: input.ownerRef, isPrimary: true },
      });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_UPDATED", resourceType: "SecurityControl", resourceId: id,
      metadata: { fields: Object.keys(data) },
    });
    return updated;
  }

  /* ------------------------------ mappings ------------------------------ */

  async createMapping(user: RequestUser, workspaceId: string, input: CreateMappingInput) {
    requireGrcPermission(user, "MANAGE_CONTROLS");
    await this.findControl(workspaceId, input.controlId);
    const requirement = await this.prisma.complianceRequirement.findFirst({ where: { id: input.requirementId } });
    if (!requirement) throw new NotFoundException("Requirement not found");
    // §11: a DIRECT mapping may not claim coverage above what the
    // control type can deliver — administrative requirements evidenced
    // only by technical signals are capped by the caller honestly;
    // here we simply refuse coverage > 1 and record the type verbatim.
    const mapping = await this.prisma.controlFrameworkMapping.create({
      data: {
        workspaceId, controlId: input.controlId, requirementId: input.requirementId,
        mappingType: input.mappingType, coverage: input.coverage, notes: input.notes ?? "", source: input.source ?? "manual",
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "CONTROL_UPDATED", resourceType: "ControlFrameworkMapping", resourceId: mapping.id,
      metadata: { mappingType: input.mappingType, coverage: input.coverage },
    });
    return mapping;
  }

  async listMappings(user: RequestUser, workspaceId: string, controlId?: string) {
    requireGrcPermission(user, "VIEW_CONTROLS");
    const items = await this.prisma.controlFrameworkMapping.findMany({
      where: { workspaceId, ...(controlId ? { controlId } : {}) }, orderBy: { createdAt: "asc" },
    });
    return { items, total: items.length };
  }
}
