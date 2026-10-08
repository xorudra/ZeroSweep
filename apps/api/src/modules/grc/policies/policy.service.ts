import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import type { CreatePolicyInput, RetentionInput, TransitionPolicyInput } from "../dto/schemas";

const TRANSITIONS: Record<string, string[]> = {
  DRAFT: ["REVIEW", "APPROVED"],
  REVIEW: ["APPROVED", "DRAFT"],
  APPROVED: ["ACTIVE"],
  ACTIVE: ["RETIRED"],
  RETIRED: [],
};

/**
 * Governance policy library (Prompt 26 §60–§63, §118). Issued
 * versions are immutable (§62): content fields of an APPROVED/ACTIVE
 * policy cannot be edited — a change is a new version row.
 * Acknowledgements are explicit records; login never implies one (§63).
 */
@Injectable()
export class PolicyService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async createPolicy(user: RequestUser, workspaceId: string, input: CreatePolicyInput) {
    requireGrcPermission(user, "MANAGE_POLICIES");
    const dupe = await this.prisma.governancePolicy.findFirst({
      where: { workspaceId, title: input.title, version: input.version },
    });
    if (dupe) throw new BadRequestException(`Policy "${input.title}" version ${input.version} already exists; versions are immutable (§62)`);
    const row = await this.prisma.governancePolicy.create({
      data: {
        workspaceId, title: input.title, ownerId: user.id, version: input.version, status: "DRAFT",
        classification: input.classification ?? "INTERNAL", documentRef: input.documentRef ?? "",
        contentHash: input.contentHash ?? "",
        effectiveDate: input.effectiveDate ? new Date(input.effectiveDate) : null,
        reviewDate: input.reviewDate ? new Date(input.reviewDate) : null,
      },
    });
    return row;
  }

  async listPolicies(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const items = await this.prisma.governancePolicy.findMany({
      where: { workspaceId }, orderBy: [{ title: "asc" }, { createdAt: "desc" }],
    });
    return { items, total: items.length };
  }

  async transitionPolicy(user: RequestUser, workspaceId: string, id: string, input: TransitionPolicyInput) {
    requireGrcPermission(user, "MANAGE_POLICIES");
    const policy = await this.prisma.governancePolicy.findFirst({ where: { id, workspaceId } });
    if (!policy) throw new NotFoundException("Policy not found in this workspace");
    if (!TRANSITIONS[policy.status]?.includes(input.status)) {
      throw new BadRequestException(`Policy cannot move ${policy.status} → ${input.status}`);
    }
    const updated = await this.prisma.governancePolicy.update({ where: { id }, data: { status: input.status } });
    if (input.status === "APPROVED") {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "POLICY_APPROVED", resourceType: "GovernancePolicy", resourceId: id,
        metadata: { title: policy.title, version: policy.version },
      });
    }
    return updated;
  }

  async acknowledge(user: RequestUser, workspaceId: string, policyId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const policy = await this.prisma.governancePolicy.findFirst({ where: { id: policyId, workspaceId } });
    if (!policy) throw new NotFoundException("Policy not found in this workspace");
    if (policy.status !== "ACTIVE") throw new BadRequestException("Only ACTIVE policies can be acknowledged");
    const existing = await this.prisma.policyAcknowledgement.findFirst({ where: { policyId, userId: user.id } });
    if (existing) return existing;
    return this.prisma.policyAcknowledgement.create({ data: { workspaceId, policyId, userId: user.id } });
  }

  async getRetention(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const row = await this.prisma.grcRetentionPolicy.findFirst({ where: { workspaceId } });
    return row ?? {
      workspaceId, assessmentRetentionDays: 2555, evidenceRetentionDays: 2555,
      packageRetentionDays: 2555, riskRetentionDays: 2555, auditRetentionDays: 2555,
    };
  }

  async updateRetention(user: RequestUser, workspaceId: string, input: RetentionInput) {
    requireGrcPermission(user, "MANAGE_POLICIES");
    const existing = await this.prisma.grcRetentionPolicy.findFirst({ where: { workspaceId } });
    const data = Object.fromEntries(Object.entries(input).filter(([, v]) => v !== undefined));
    return existing
      ? this.prisma.grcRetentionPolicy.update({ where: { id: existing.id }, data })
      : this.prisma.grcRetentionPolicy.create({ data: { workspaceId, ...data } });
  }
}
