import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { evaluateLicense, parseLicenseDocument, type LicenseEvaluation } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { ProductConfigService } from "../product-config.service";
import { EntitlementService } from "../entitlements/entitlement.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface LicenseView {
  installed: boolean;
  license: any | null;
  evaluation: LicenseEvaluation | null;
  licensingEnabled: boolean;
}

/**
 * Self-hosted license lifecycle (Prompt 40 §28–§37, §110–§112).
 *
 * Install verifies the Ed25519 signature against the deployment's
 * configured PUBLIC key (§31) before persisting anything; a rejected
 * license is audited (LICENSE_REJECTED) and never stored (§215).
 * Verification is fully offline (§36). The signature/payload are kept
 * for re-verification; no key material is ever returned by the API
 * (§105/§110).
 */
@Injectable()
export class LicenseService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: ProductConfigService,
    private readonly entitlements: EntitlementService,
  ) {}

  private evaluateStored(license: any): LicenseEvaluation {
    const pub = this.config.licensePublicKey()!;
    return evaluateLicense(
      {
        payload: {
          licenseId: license.licenseId, organization: license.organization, edition: license.edition, issuer: license.issuer,
          issuedAt: new Date(license.issuedAt).toISOString(), validFrom: new Date(license.validFrom).toISOString(), expiresAt: new Date(license.expiresAt).toISOString(),
          entitlements: license.entitlements, limits: license.limits,
        },
        signature: license.signature, algorithm: "Ed25519",
      },
      pub,
      { now: new Date(), graceDays: this.config.licenseGraceDays() },
    );
  }

  async install(actor: { id: string; organizationId: string }, documentText: string): Promise<LicenseView> {
    const pub = this.config.licensePublicKey();
    if (!pub) {
      throw new BadRequestException("Self-hosted licensing is not enabled in this deployment: no license verification public key is configured (§269). Nothing was installed.");
    }
    let document;
    try {
      document = parseLicenseDocument(documentText);
    } catch {
      await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "LICENSE_REJECTED", resourceType: "ProductLicense", metadata: { reason: "malformed document" } });
      throw new BadRequestException("License document is malformed; installation rejected (§32).");
    }
    const evaluation = evaluateLicense(document, pub, {
      now: new Date(), graceDays: this.config.licenseGraceDays(),
    });
    if (evaluation.status === "INVALID" || evaluation.status === "REVOKED") {
      await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "LICENSE_REJECTED", resourceType: "ProductLicense", metadata: { licenseId: document.payload.licenseId, reason: evaluation.reason } });
      throw new BadRequestException(`License rejected: ${evaluation.reason}`);
    }
    const p = document.payload;
    const row = await (this.prisma as any).productLicense.upsert({
      where: { licenseId: p.licenseId },
      create: {
        licenseId: p.licenseId, organizationId: actor.organizationId, organization: p.organization, edition: p.edition, issuer: p.issuer,
        issuedAt: new Date(p.issuedAt), validFrom: new Date(p.validFrom), expiresAt: new Date(p.expiresAt),
        entitlements: p.entitlements as never, limits: p.limits as never, signature: document.signature,
        status: evaluation.status, installedById: actor.id,
      },
      update: {
        organizationId: actor.organizationId, organization: p.organization, edition: p.edition, issuer: p.issuer,
        issuedAt: new Date(p.issuedAt), validFrom: new Date(p.validFrom), expiresAt: new Date(p.expiresAt),
        entitlements: p.entitlements as never, limits: p.limits as never, signature: document.signature,
        status: evaluation.status, installedById: actor.id,
      },
    });
    this.entitlements.invalidate(actor.organizationId);
    await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "LICENSE_INSTALLED", resourceType: "ProductLicense", resourceId: row.id, metadata: { licenseId: p.licenseId, edition: p.edition, status: evaluation.status } });
    return this.getCurrent(actor.organizationId);
  }

  /** §110/§112: safe license view — status + entitlements, never key material. */
  async getCurrent(organizationId: string): Promise<LicenseView> {
    const pub = this.config.licensePublicKey();
    if (!pub) return { installed: false, license: null, evaluation: null, licensingEnabled: false };
    const license = await (this.prisma as any).productLicense.findFirst({
      where: { OR: [{ organizationId }, { organizationId: null }] }, orderBy: { installedAt: "desc" },
    });
    if (!license) return { installed: false, license: null, evaluation: null, licensingEnabled: true };
    const evaluation = this.evaluateStored(license);
    if (evaluation.status !== license.status) {
      await (this.prisma as any).productLicense.update({ where: { id: license.id }, data: { status: evaluation.status } });
      if (evaluation.status === "EXPIRED") {
        await this.audit.record({ organizationId, action: "LICENSE_EXPIRED", resourceType: "ProductLicense", resourceId: license.id, metadata: { licenseId: license.licenseId, dataPreserved: true } }).catch(() => undefined);
      }
    }
    const { signature: _signature, ...safe } = license;
    return { installed: true, license: safe, evaluation, licensingEnabled: true };
  }
}
