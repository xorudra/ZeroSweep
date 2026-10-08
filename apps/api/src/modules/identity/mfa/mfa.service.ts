import { BadRequestException, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import {
  base32Decode, decryptSecret, encryptSecret, generateRecoveryCodes as genCodes, generateTotpSecret,
  hashRecoveryCode, isPrivilegedOrgRole, platformKeyFromMaterial, totpSetupUri, verifyRecoveryCode, verifyTotp,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { SecretResolver } from "../secret-resolver";
import type { RequestUser } from "../../../common/decorators/auth.decorators";

/**
 * MFA (§24–30, §35): TOTP with AES-256-GCM-encrypted secrets, one-time
 * hashed recovery codes, replay protection via persisted time-step, and
 * policy evaluation (OPTIONAL / REQUIRED_FOR_ADMINS / REQUIRED_FOR_ALL).
 * Secrets are returned exactly once — at enrollment — and never logged.
 */
@Injectable()
export class MfaService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly secrets: SecretResolver,
  ) {}

  private key(): Buffer {
    return platformKeyFromMaterial(this.secrets.platformKeyMaterial());
  }

  async policyGate(organizationId: string, userId: string, role: string): Promise<{ required: boolean; enrolled: boolean; reason: string }> {
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId } });
    const requirement = (policy?.mfaRequirement as string) ?? "OPTIONAL";
    const enrolled = (await this.prisma.mfaMethod.count({ where: { userId, type: "TOTP", isActive: true } })) > 0
      || (await this.prisma.webAuthnCredential.count({ where: { userId } })) > 0;
    if (requirement === "REQUIRED_FOR_ALL") return { required: true, enrolled, reason: "Organization requires MFA for all users" };
    if (requirement === "REQUIRED_FOR_ADMINS" && isPrivilegedOrgRole(role)) return { required: true, enrolled, reason: "Organization requires MFA for administrators" };
    // Even under OPTIONAL, an enrolled user must complete MFA at login.
    if (enrolled) return { required: true, enrolled, reason: "MFA is enrolled for this account" };
    return { required: false, enrolled, reason: "MFA not required" };
  }

  /** Begin TOTP enrollment: secret is shown ONCE (§26). A pending method is
   *  stored encrypted; it only activates after a valid first code. */
  async enrollTotp(user: RequestUser) {
    const { secretBase32 } = generateTotpSecret();
    const pending = await this.prisma.mfaMethod.findFirst({ where: { userId: user.id, type: "TOTP", isActive: false } });
    const encrypted = encryptSecret(secretBase32, this.key());
    if (pending) await this.prisma.mfaMethod.update({ where: { id: pending.id }, data: { secretEncrypted: encrypted } });
    else await this.prisma.mfaMethod.create({ data: { userId: user.id, type: "TOTP", secretEncrypted: encrypted, isActive: false } });
    return { secret: secretBase32, setupUri: totpSetupUri(secretBase32, user.email), shownOnce: true };
  }

  async activateTotp(user: RequestUser, code: string) {
    const method = await this.prisma.mfaMethod.findFirst({ where: { userId: user.id, type: "TOTP", isActive: false } });
    if (!method?.secretEncrypted) throw new BadRequestException("No pending TOTP enrollment");
    const secret = base32Decode(decryptSecret(method.secretEncrypted as string, this.key()));
    const result = verifyTotp(secret, code, Date.now(), null);
    if (!result.ok) throw new UnauthorizedException("Invalid verification code");
    await this.prisma.mfaMethod.update({ where: { id: method.id }, data: { isActive: true, lastUsedStep: result.matchedStep, lastUsedAt: new Date() } });
    await this.prisma.authenticationEvent.create({ data: { userId: user.id, organizationId: user.organizationId, eventType: "MFA_SUCCESS" } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "MFA_ENABLED", resourceType: "MfaMethod", resourceId: method.id as string });
    return { enrolled: true };
  }

  /** Verify a TOTP code for an enrolled user (login challenge / step-up).
   *  Replay of an accepted time-step is rejected (§28). */
  async verifyTotpForUser(userId: string, organizationId: string, code: string): Promise<boolean> {
    const method = await this.prisma.mfaMethod.findFirst({ where: { userId, type: "TOTP", isActive: true } });
    if (!method?.secretEncrypted) return false;
    const secret = base32Decode(decryptSecret(method.secretEncrypted as string, this.key()));
    const lastStep = method.lastUsedStep != null ? BigInt(method.lastUsedStep as never) : null;
    const result = verifyTotp(secret, code, Date.now(), lastStep);
    if (!result.ok) {
      await this.prisma.authenticationEvent.create({ data: { userId, organizationId, eventType: "MFA_FAILED" } });
      return false;
    }
    await this.prisma.mfaMethod.update({ where: { id: method.id }, data: { lastUsedStep: result.matchedStep, lastUsedAt: new Date() } });
    await this.prisma.authenticationEvent.create({ data: { userId, organizationId, eventType: "MFA_SUCCESS" } });
    return true;
  }

  /** Generate a fresh recovery-code set (§29): old codes are destroyed,
   *  plaintext is returned exactly once, only hashes persist. */
  async generateRecoveryCodes(user: RequestUser) {
    const codes = genCodes(10);
    await this.prisma.recoveryCode.deleteMany({ where: { userId: user.id } });
    for (const code of codes) {
      await this.prisma.recoveryCode.create({ data: { userId: user.id, codeHash: hashRecoveryCode(code) } });
    }
    const marker = await this.prisma.mfaMethod.findFirst({ where: { userId: user.id, type: "RECOVERY_CODES" } });
    if (!marker) await this.prisma.mfaMethod.create({ data: { userId: user.id, type: "RECOVERY_CODES", isActive: true } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "RECOVERY_CODES_REGENERATED", resourceType: "User", resourceId: user.id });
    return { codes, shownOnce: true };
  }

  /** Consume a recovery code (§30): single use, invalidated immediately,
   *  audited without recording the plaintext. */
  async consumeRecoveryCode(userId: string, organizationId: string, code: string): Promise<boolean> {
    const rows = await this.prisma.recoveryCode.findMany({ where: { userId, usedAt: null } });
    for (const row of rows) {
      if (verifyRecoveryCode(code, row.codeHash as string)) {
        await this.prisma.recoveryCode.update({ where: { id: row.id }, data: { usedAt: new Date() } });
        await this.prisma.authenticationEvent.create({ data: { userId, organizationId, eventType: "RECOVERY_USED" } });
        await this.audit.record({ actorId: userId, organizationId, action: "RECOVERY_CODE_USED", resourceType: "RecoveryCode", resourceId: row.id as string });
        return true;
      }
    }
    return false;
  }

  async status(userId: string) {
    const [totpActive, passkeys, recoveryRemaining] = await Promise.all([
      this.prisma.mfaMethod.count({ where: { userId, type: "TOTP", isActive: true } }),
      this.prisma.webAuthnCredential.count({ where: { userId } }),
      this.prisma.recoveryCode.count({ where: { userId, usedAt: null } }),
    ]);
    return { totpEnrolled: totpActive > 0, passkeyCount: passkeys, recoveryCodesRemaining: recoveryRemaining };
  }

  /** Controlled MFA reset (§112): admin action, strongly audited; the user's
   *  methods are removed and their sessions revoked by the caller flow. */
  async adminResetMfa(actor: RequestUser, targetUserId: string) {
    await this.prisma.mfaMethod.deleteMany({ where: { userId: targetUserId } });
    await this.prisma.webAuthnCredential.deleteMany({ where: { userId: targetUserId } });
    await this.prisma.recoveryCode.deleteMany({ where: { userId: targetUserId } });
    await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "MFA_RESET", resourceType: "User", resourceId: targetUserId });
    await this.prisma.authenticationEvent.create({ data: { userId: targetUserId, organizationId: actor.organizationId, eventType: "MFA_RESET" } });
    return { reset: true };
  }
}
