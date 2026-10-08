import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import type { AssessVendorInput, CreateVendorInput } from "../dto/schemas";

/**
 * Vendor risk foundation (Prompt 26 §106–§108). Deliberately minimal:
 * vendor identity, criticality, review cadence and risk assessments.
 * No unnecessary personal data is collected (§107) — contacts and
 * personal details are not fields of this model at all.
 */
@Injectable()
export class VendorService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async createVendor(user: RequestUser, workspaceId: string, input: CreateVendorInput) {
    requireGrcPermission(user, "MANAGE_VENDOR_RISK");
    const row = await this.prisma.thirdPartyVendor.create({
      data: {
        workspaceId, name: input.name, ownerId: user.id, criticality: input.criticality ?? "MEDIUM",
        serviceDescription: input.serviceDescription ?? "", status: "ACTIVE",
        reviewDate: input.reviewDate ? new Date(input.reviewDate) : null, riskRating: null,
      },
    });
    return row;
  }

  async listVendors(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const items = await this.prisma.thirdPartyVendor.findMany({
      where: { workspaceId }, orderBy: { name: "asc" },
    });
    return { items, total: items.length };
  }

  async assessVendor(user: RequestUser, workspaceId: string, vendorId: string, input: AssessVendorInput) {
    requireGrcPermission(user, "MANAGE_VENDOR_RISK");
    const vendor = await this.prisma.thirdPartyVendor.findFirst({ where: { id: vendorId, workspaceId } });
    if (!vendor) throw new NotFoundException("Vendor not found in this workspace");
    const row = await this.prisma.vendorRiskAssessment.create({
      data: {
        workspaceId, vendorId, method: input.method ?? "QUESTIONNAIRE", riskRating: input.riskRating,
        findings: input.findings ?? "", treatment: input.treatment ?? "",
        evidenceIds: input.evidenceIds ?? [], assessedBy: user.id,
      },
    });
    await this.prisma.thirdPartyVendor.update({
      where: { id: vendorId }, data: { riskRating: input.riskRating, status: "ACTIVE" },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RISK_UPDATED", resourceType: "ThirdPartyVendor", resourceId: vendorId,
      metadata: { riskRating: input.riskRating, method: row.method },
    });
    return row;
  }
}
