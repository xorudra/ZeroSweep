import { BadRequestException, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import {
  randomToken, sha256Hex, verifyAssertion, verifyRegistration,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";

/**
 * WebAuthn / passkeys (§31–34). Challenges are single-use, hashed at rest,
 * and bound to the user + ceremony. Registration and authentication are
 * verified with the SDK's node:crypto implementation (challenge, origin,
 * RP ID, signature, counter). Only public keys persist.
 */
@Injectable()
export class WebAuthnService {
  private readonly rpId = process.env.WEBAUTHN_RP_ID ?? "localhost";
  private readonly origin = process.env.WEBAUTHN_ORIGIN ?? "http://localhost:3000";

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async registrationOptions(user: RequestUser) {
    const challenge = randomToken(32);
    await this.prisma.authChallenge.create({
      data: { userId: user.id, type: "WEBAUTHN_REGISTRATION", tokenHash: sha256Hex(challenge), expiresAt: new Date(Date.now() + 5 * 60_000) },
    });
    return { challenge, rpId: this.rpId, origin: this.origin, userVerification: "preferred" as const };
  }

  async register(user: RequestUser, body: { challenge: string; attestationObject: string; clientDataJSON: string; friendlyName?: string; passkey?: boolean }) {
    const record = await this.takeChallenge(user.id, "WEBAUTHN_REGISTRATION", body.challenge);
    if (!record) throw new UnauthorizedException("Registration challenge expired or invalid");
    let result;
    try {
      result = verifyRegistration({
        attestationObject: Buffer.from(body.attestationObject, "base64url"),
        clientDataJSON: Buffer.from(body.clientDataJSON, "base64url"),
        check: { expectedType: "webauthn.create", expectedChallenge: body.challenge, expectedOrigin: this.origin },
        rpId: this.rpId, requireUserVerification: false,
      });
    } catch (err) {
      throw new BadRequestException(`Passkey registration failed: ${(err as Error).message}`);
    }
    const existing = await this.prisma.webAuthnCredential.findUnique({ where: { credentialId: result.credentialId } });
    if (existing) throw new BadRequestException("Credential already registered");
    const credential = await this.prisma.webAuthnCredential.create({
      data: {
        userId: user.id, credentialId: result.credentialId, publicKey: result.publicKeyCoseBase64url,
        counter: BigInt(result.signCount), friendlyName: body.friendlyName ?? null, isPasskey: body.passkey ?? true,
      },
    });
    const method = await this.prisma.mfaMethod.findFirst({ where: { userId: user.id, type: body.passkey ? "PASSKEY" : "WEBAUTHN", credentialId: result.credentialId } });
    if (!method) await this.prisma.mfaMethod.create({ data: { userId: user.id, type: body.passkey ? "PASSKEY" : "WEBAUTHN", credentialId: result.credentialId, isActive: true } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "PASSKEY_REGISTERED", resourceType: "WebAuthnCredential", resourceId: credential.id as string });
    return { registered: true, credentialId: result.credentialId };
  }

  async authenticationOptions(userId: string) {
    const challenge = randomToken(32);
    await this.prisma.authChallenge.create({
      data: { userId, type: "WEBAUTHN_AUTHENTICATION", tokenHash: sha256Hex(challenge), expiresAt: new Date(Date.now() + 5 * 60_000) },
    });
    const credentials = await this.prisma.webAuthnCredential.findMany({ where: { userId } });
    return { challenge, rpId: this.rpId, origin: this.origin, allowCredentials: credentials.map((c) => c.credentialId) };
  }

  /** Verify an assertion for login/step-up. Returns true only on a valid,
   *  fresh, counter-advancing signature (§34, §121). */
  async authenticate(userId: string, organizationId: string, body: { challenge: string; credentialId: string; authenticatorData: string; clientDataJSON: string; signature: string }): Promise<boolean> {
    const record = await this.takeChallenge(userId, "WEBAUTHN_AUTHENTICATION", body.challenge);
    if (!record) return false;
    const credential = await this.prisma.webAuthnCredential.findUnique({ where: { credentialId: body.credentialId } });
    if (!credential || credential.userId !== userId) return false;
    try {
      const result = verifyAssertion({
        authenticatorData: Buffer.from(body.authenticatorData, "base64url"),
        clientDataJSON: Buffer.from(body.clientDataJSON, "base64url"),
        signature: Buffer.from(body.signature, "base64url"),
        publicKeyCoseBase64url: credential.publicKey as string,
        check: { expectedType: "webauthn.get", expectedChallenge: body.challenge, expectedOrigin: this.origin },
        rpId: this.rpId, requireUserVerification: false,
        storedSignCount: Number(credential.counter),
      });
      await this.prisma.webAuthnCredential.update({ where: { id: credential.id }, data: { counter: BigInt(result.signCount), lastUsedAt: new Date() } });
      await this.prisma.authenticationEvent.create({ data: { userId, organizationId, eventType: "PASSKEY_LOGIN" } });
      return true;
    } catch {
      await this.prisma.authenticationEvent.create({ data: { userId, organizationId, eventType: "MFA_FAILED" } });
      return false;
    }
  }

  async listCredentials(user: RequestUser) {
    const rows = await this.prisma.webAuthnCredential.findMany({ where: { userId: user.id }, orderBy: { createdAt: "desc" } });
    return rows.map((c) => ({ id: c.id, credentialId: c.credentialId, friendlyName: c.friendlyName, isPasskey: c.isPasskey, createdAt: c.createdAt, lastUsedAt: c.lastUsedAt }));
  }

  async removeCredential(user: RequestUser, id: string) {
    const credential = await this.prisma.webAuthnCredential.findFirst({ where: { id, userId: user.id } });
    if (!credential) throw new BadRequestException("Credential not found");
    await this.prisma.webAuthnCredential.delete({ where: { id } });
    await this.prisma.mfaMethod.deleteMany({ where: { userId: user.id, credentialId: credential.credentialId } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "PASSKEY_REMOVED", resourceType: "WebAuthnCredential", resourceId: id });
    return { removed: true };
  }

  private async takeChallenge(userId: string, type: string, challenge: string) {
    const record = await this.prisma.authChallenge.findUnique({ where: { tokenHash: sha256Hex(challenge) } });
    if (!record || record.userId !== userId || record.type !== type || record.consumedAt) return null;
    if (new Date(record.expiresAt as Date).getTime() < Date.now()) return null;
    await this.prisma.authChallenge.update({ where: { id: record.id }, data: { consumedAt: new Date(), attempts: (record.attempts as number) + 1 } });
    return record;
  }
}
