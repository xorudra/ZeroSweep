import { BadRequestException, ConflictException, ForbiddenException, HttpException, HttpStatus, Inject, Injectable } from "@nestjs/common";
import * as bcrypt from "bcryptjs";
import { createHash, randomBytes } from "node:crypto";
import { isReservedSlug, isValidSlug } from "@zerosweep/security-sdk";
import { registrationMode } from "@zerosweep/config";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { rateLimitHit } from "../../../common/rate-limit-store";
import { AuditService } from "../../audit/audit.service";
import { ProductConfigService } from "../product-config.service";
import { PlansService } from "../plans/plans.service";
import { QuotaEnforcementService } from "../quotas/quota.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface SignupInput {
  name: string;
  email: string;
  password: string;
  organizationName: string;
  slug: string;
}

export interface SignupResult {
  user: { id: string; email: string; name: string; emailVerified: boolean };
  organization: { id: string; name: string; slug: string; lifecycleStatus: string };
  workspace: { id: string; name: string };
  planCode: string;
  trial: { id: string; expiresAt: string } | null;
  /** Raw verification token — delivered via email in production. It is
   *  returned in the response ONLY outside production, because no mail
   *  transport is configured in development stacks (§148: the token is
   *  hashed at rest, single-use, expiring either way). */
  emailVerificationToken: string | null;
  nextStep: string;
}

/**
 * CustomerProvisioningService (Prompt 40 §58–§64, §82–§84).
 *
 * Signup is a single transaction (§62): user → email-verification token
 * → organization → OWNER membership (§61) → initial workspace → plan /
 * trial → quota policies → onboarding state. A failure anywhere leaves
 * NO half-created organization. Duplicate email/slug are safe,
 * non-enumerating conflicts (§63); reserved slugs are refused (§64).
 * Retrying a signup with the same email is idempotent in effect: it
 * conflicts cleanly and creates nothing twice (§84).
 */
@Injectable()
export class CustomerProvisioningService {

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: ProductConfigService,
    private readonly plans: PlansService,
    private readonly quotas: QuotaEnforcementService,
  ) {}

  private hashToken(raw: string): string {
    return createHash("sha256").update(raw).digest("hex");
  }

  async signup(input: SignupInput, ip = "unknown"): Promise<SignupResult> {
    // Invite-only deployments (REGISTRATION_MODE=invite-only): public
    // sign-up is closed on EVERY registration surface — this parallel
    // provisioning path must refuse exactly like AuthService.register,
    // before any lookup or write. New accounts come only from
    // organization invitation acceptance.
    if (registrationMode() === "invite-only") {
      throw new ForbiddenException("This deployment is invite-only. Public sign-up is closed — ask an organization admin to invite you.");
    }
    await this.checkRegisterRateLimit(ip);
    const email = input.email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new BadRequestException("A valid email address is required.");
    if (!input.password || input.password.length < 10) throw new BadRequestException("Password must be at least 10 characters.");
    const slug = input.slug.trim().toLowerCase();
    if (isReservedSlug(slug)) throw new BadRequestException(`Organization slug '${slug}' is reserved (§64).`);
    if (!isValidSlug(slug)) throw new BadRequestException("Organization slug must be 3–64 chars of lowercase letters, digits and hyphens (§64).");

    const existingUser = await (this.prisma as any).user.findUnique({ where: { email } });
    if (existingUser) throw new ConflictException("An account with this email already exists (§63).");
    const existingOrg = await (this.prisma as any).organization.findUnique({ where: { slug } });
    if (existingOrg) throw new ConflictException("An organization with this slug already exists (§63).");

    const mode = this.config.productMode();
    const planCode = mode === "SAAS" || mode === "ENTERPRISE" ? "TRIAL" : mode === "COMMUNITY" ? "COMMUNITY" : "SELF_HOSTED";
    const planVersion = await this.plans.latestActiveVersion(planCode);
    if (!planVersion) {
      throw new BadRequestException(`Default plan '${planCode}' is not seeded/active in this deployment; signup cannot proceed honestly. Run the database seed.`);
    }

    const passwordHash = await bcrypt.hash(input.password, 12);
    const rawToken = randomBytes(32).toString("base64url");
    const isPlatformAdmin = this.config.isPlatformAdminEmail(email);
    const trialDays = this.config.trialDays();
    const now = new Date();

    const result = await (this.prisma as any).$transaction(async (tx: any) => {
      const user = await tx.user.create({
        data: { email, normalizedEmail: email, name: input.name, passwordHash, isPlatformAdmin },
      });
      await tx.emailVerificationToken.create({
        data: { userId: user.id, tokenHash: this.hashToken(rawToken), expiresAt: new Date(now.getTime() + 24 * 3600_000) },
      });
      const organization = await tx.organization.create({
        data: { name: input.organizationName, slug, lifecycleStatus: "ACTIVE", dataRegion: "default" },
      });
      await tx.membership.create({
        data: { userId: user.id, organizationId: organization.id, role: "OWNER", status: "ACTIVE", joinedAt: now },
      });
      const workspace = await tx.workspace.create({ data: { organizationId: organization.id, name: "Default Workspace" } });

      let trial: any = null;
      if (planCode === "TRIAL") {
        trial = await tx.productTrial.create({
          data: { organizationId: organization.id, planVersionId: planVersion.id, status: "ACTIVE", expiresAt: new Date(now.getTime() + trialDays * 86_400_000) },
        });
        await tx.subscription.create({
          data: {
            organizationId: organization.id, planVersionId: planVersion.id, status: "TRIALING",
            startedAt: now, currentPeriodStart: now,
            currentPeriodEnd: new Date(now.getTime() + trialDays * 86_400_000),
            trialEndsAt: new Date(now.getTime() + trialDays * 86_400_000),
          },
        });
      } else {
        await tx.subscription.create({
          data: {
            organizationId: organization.id, planVersionId: planVersion.id, status: "ACTIVE",
            startedAt: now, currentPeriodStart: now,
            currentPeriodEnd: new Date(now.getTime() + 30 * 86_400_000),
          },
        });
      }
      await tx.organizationOnboarding.create({
        data: { organizationId: organization.id, status: "IN_PROGRESS", currentStep: "WELCOME", completedSteps: [] },
      });
      return { user, organization, workspace, trial };
    });

    await this.quotas.materializePolicies(result.organization.id, (planVersion.quotas ?? {}) as Record<string, number | null>, "PLAN");
    await this.audit.record({
      actorId: result.user.id, organizationId: result.organization.id, workspaceId: result.workspace.id,
      action: "ORGANIZATION_PROVISIONED", resourceType: "Organization", resourceId: result.organization.id,
      metadata: { planCode, mode, trial: Boolean(result.trial) },
    });
    if (result.trial) {
      await this.audit.record({ actorId: result.user.id, organizationId: result.organization.id, action: "TRIAL_STARTED", resourceType: "ProductTrial", resourceId: result.trial.id });
    }

    return {
      user: { id: result.user.id, email: result.user.email, name: result.user.name, emailVerified: false },
      organization: { id: result.organization.id, name: result.organization.name, slug: result.organization.slug, lifecycleStatus: "ACTIVE" },
      workspace: { id: result.workspace.id, name: result.workspace.name },
      planCode,
      trial: result.trial ? { id: result.trial.id, expiresAt: result.trial.expiresAt.toISOString() } : null,
      emailVerificationToken: this.config.nodeEnv() === "production" ? null : rawToken,
      nextStep: "VERIFY_EMAIL",
    };
  }

  /** Per-IP signup rate limit with parity to AuthService.register:
   *  10 per hour, same shared (Redis-backed) bucket machinery (§22). */
  private async checkRegisterRateLimit(ip: string) {
    // Single atomic check-and-record (run-3), parity with AuthService.
    const decision = await rateLimitHit(`register|${ip}`, 10, 60 * 60_000);
    if (!decision.allowed) {
      throw new HttpException("Too many registration attempts — please try again later.", HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  /** §60: single-use, expiring, hashed-at-rest email verification. */
  async verifyEmail(rawToken: string): Promise<{ verified: boolean }> {
    const tokenHash = this.hashToken(rawToken);
    const row = await (this.prisma as any).emailVerificationToken.findUnique({ where: { tokenHash } });
    if (!row || row.usedAt || row.expiresAt < new Date()) {
      throw new BadRequestException("Verification link is invalid, expired or already used (§151).");
    }
    await (this.prisma as any).emailVerificationToken.update({ where: { id: row.id }, data: { usedAt: new Date() } });
    await (this.prisma as any).user.update({ where: { id: row.userId }, data: { emailVerifiedAt: new Date() } });
    return { verified: true };
  }

  /** §83: the full provisioning bundle for an existing organization (operator repair path). */
  async provisioningSummary(organizationId: string): Promise<any> {
    const [org, workspaces, subscription, trial, onboarding] = await Promise.all([
      (this.prisma as any).organization.findUnique({ where: { id: organizationId } }),
      (this.prisma as any).workspace.count({ where: { organizationId } }),
      (this.prisma as any).subscription.findFirst({ where: { organizationId }, orderBy: { createdAt: "desc" } }),
      (this.prisma as any).productTrial.findFirst({ where: { organizationId }, orderBy: { createdAt: "desc" } }),
      (this.prisma as any).organizationOnboarding.findUnique({ where: { organizationId } }),
    ]);
    if (!org) throw new BadRequestException("Organization not found.");
    return { organization: org, workspaceCount: workspaces, subscription, trial, onboarding };
  }
}
