import { Injectable } from "@nestjs/common";
import { isPlatformAdminEmail, loadEnv, type AppEnv } from "@dsrclone/config";
import { billingConfigurationStatus, type ProductMode } from "@dsrclone/security-sdk";

/**
 * Product configuration (Prompt 40 §3/§4). The product mode, billing
 * provider, license verification key and platform-admin bootstrap list
 * come ONLY from trusted deployment configuration. No tenant-facing API
 * can read the raw secrets or change these values.
 */
@Injectable()
export class ProductConfigService {
  private readonly env: AppEnv;

  constructor() {
    this.env = loadEnv();
  }

  productMode(): ProductMode {
    return this.env.PRODUCT_MODE;
  }

  nodeEnv(): string {
    return this.env.NODE_ENV;
  }

  releaseVersion(): string {
    return this.env.RELEASE_VERSION;
  }

  billing() {
    return billingConfigurationStatus({ provider: this.env.PRODUCT_BILLING_PROVIDER ?? null, nodeEnv: this.env.NODE_ENV });
  }

  billingWebhookSecret(): string | null {
    return this.env.PRODUCT_BILLING_WEBHOOK_SECRET ?? null;
  }

  /** Ed25519 verification public key (§31). Null => licensing not enabled (§269). */
  licensePublicKey(): string | null {
    const raw = this.env.PRODUCT_LICENSE_PUBLIC_KEY;
    if (!raw) return null;
    // PEMs are commonly supplied with literal \n escapes in env stores.
    return raw.includes("\\n") ? raw.replace(/\\n/g, "\n") : raw;
  }

  licensingEnabled(): boolean {
    return this.licensePublicKey() !== null;
  }

  licenseGraceDays(): number {
    return this.env.PRODUCT_LICENSE_GRACE_DAYS;
  }

  trialDays(): number {
    return this.env.PRODUCT_TRIAL_DAYS;
  }

  telemetryEnabled(): boolean {
    return this.env.PRODUCT_TELEMETRY_ENABLED;
  }

  updateChecksEnabled(): boolean {
    return this.env.PRODUCT_UPDATE_CHECKS_ENABLED;
  }

  /** §96 bootstrap: deployment-configured platform admin emails. */
  isPlatformAdminEmail(email: string): boolean {
    return isPlatformAdminEmail(email, this.env);
  }

  /** Safe, secret-free view for diagnostics (§207): keys, never values. */
  configurationSummary(): Record<string, unknown> {
    return {
      NODE_ENV: this.env.NODE_ENV,
      PRODUCT_MODE: this.env.PRODUCT_MODE,
      PRODUCT_BILLING_PROVIDER: this.env.PRODUCT_BILLING_PROVIDER ?? null,
      PRODUCT_LICENSE_PUBLIC_KEY: this.env.PRODUCT_LICENSE_PUBLIC_KEY ? "[configured]" : null,
      PRODUCT_LICENSE_GRACE_DAYS: this.env.PRODUCT_LICENSE_GRACE_DAYS,
      PRODUCT_TRIAL_DAYS: this.env.PRODUCT_TRIAL_DAYS,
      PRODUCT_TELEMETRY_ENABLED: this.env.PRODUCT_TELEMETRY_ENABLED,
      RELEASE_VERSION: this.env.RELEASE_VERSION,
    };
  }
}
