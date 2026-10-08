import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { ONBOARDING_DEFAULT_ASSESSMENT_PROFILE, ONBOARDING_STEPS, canCompleteStep, onboardingProgress } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * OnboardingService (Prompt 40 §65–§75).
 *
 * Steps are ordered; optional steps may be skipped (§68) but security
 * steps may not (§69). The SECURITY_SCOPE step records the
 * authorization attestation (§70/§168): the customer attests they are
 * authorized to test the assets they add — the platform's existing
 * verified-target + scope machinery still applies to every assessment
 * (§71). The FIRST_ASSESSMENT step records guided-flow completion; the
 * assessment itself runs through the governed scan flow with the SAFE
 * standard profile by default (§72/§73).
 */
@Injectable()
export class OnboardingService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async getState(organizationId: string): Promise<any> {
    let row = await (this.prisma as any).organizationOnboarding.findUnique({ where: { organizationId } });
    if (!row) {
      row = await (this.prisma as any).organizationOnboarding.create({
        data: { organizationId, status: "IN_PROGRESS", currentStep: "WELCOME", completedSteps: [] },
      });
    }
    const completedSteps = (row.completedSteps ?? []) as string[];
    const skippedSteps = (row.skippedSteps ?? []) as string[];
    return {
      ...row,
      defaultAssessmentProfile: ONBOARDING_DEFAULT_ASSESSMENT_PROFILE,
      steps: ONBOARDING_STEPS.map((s) => ({
        ...s,
        completed: completedSteps.includes(s.key),
        state: completedSteps.includes(s.key) ? "COMPLETED" : skippedSteps.includes(s.key) ? "SKIPPED" : "PENDING",
        available: canCompleteStep(s.key, completedSteps).ok,
      })),
      progress: onboardingProgress(completedSteps),
      authorizationAttested: Boolean(row.authorizationAttestedAt),
    };
  }

  async completeStep(user: { id: string; organizationId: string }, stepKey: string, payload?: { attested?: boolean }): Promise<any> {
    const organizationId = user.organizationId;
    const state = await this.getState(organizationId);
    const completedSteps = [...((state.completedSteps ?? []) as string[])];
    if (completedSteps.includes(stepKey)) return state;
    const check = canCompleteStep(stepKey, completedSteps);
    if (!check.ok) throw new BadRequestException(check.reason);

    if (stepKey === "SECURITY_SCOPE") {
      if (!payload?.attested) {
        throw new BadRequestException("The Security Scope step requires an explicit authorization attestation (§70/§168): you may only assess assets you own or are authorized to test.");
      }
      await (this.prisma as any).organizationOnboarding.update({
        where: { organizationId },
        data: { authorizationAttestedAt: new Date(), authorizationAttestedById: user.id },
      });
      await this.audit.record({ actorId: user.id, organizationId, action: "TARGET_VERIFIED", resourceType: "OrganizationOnboarding", metadata: { attestation: "AUTHORIZATION_ATTESTED", step: stepKey } }).catch(() => undefined);
    }

    completedSteps.push(stepKey);
    const progress = onboardingProgress(completedSteps);
    const isDone = progress.nextStep === null;
    await (this.prisma as any).organizationOnboarding.update({
      where: { organizationId },
      data: {
        completedSteps,
        currentStep: progress.nextStep ?? "COMPLETION",
        status: isDone ? "COMPLETED" : "IN_PROGRESS",
        completedAt: isDone ? new Date() : null,
      },
    });
    return this.getState(organizationId);
  }

  /** Optional steps only (§68). Security-critical steps can never be skipped. */
  async skipStep(user: { id: string; organizationId: string }, stepKey: string): Promise<any> {
    const def = ONBOARDING_STEPS.find((s) => s.key === stepKey);
    if (!def) throw new BadRequestException(`Unknown onboarding step '${stepKey}'.`);
    if (!def.optional || def.securityCritical) throw new BadRequestException(`Step ${stepKey} cannot be skipped (§68/§69).`);
    return this.completeStep(user, stepKey);
  }
}
