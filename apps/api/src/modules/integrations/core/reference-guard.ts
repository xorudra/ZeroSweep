import { BadRequestException } from "@nestjs/common";
import { isTenantSecretSlotReference } from "@dsrclone/config";

/**
 * Write-site guard for tenant-controlled secret references (security
 * audit 2026-10-16): the resolver only ever resolves operator-
 * provisioned tenant slots (`env:TENANT_SECRET_*`), and a reference
 * naming any other `env:` variable is rejected HERE, at write time,
 * with a 400 — so a stored reference can never turn a platform
 * variable into a signing oracle or credential. Non-`env:` references
 * (secret-manager names) are opaque and unresolvable in this layer;
 * they are not the oracle channel and stay allowed.
 */
export function assertSecretReferenceAllowed(reference: unknown, field = "secretReference"): void {
  if (typeof reference !== "string" || reference.length === 0) return;
  if (reference.startsWith("env:") && !isTenantSecretSlotReference(reference)) {
    throw new BadRequestException(
      `${field} must reference an operator-provisioned tenant secret slot (env:TENANT_SECRET_*) — platform environment variables cannot be referenced`,
    );
  }
}

/** Deep-walk a non-secret configuration object: every string value
 *  that is an `env:` reference must be a tenant slot reference. */
export function assertConfigurationSecretReferences(config: unknown, field = "configuration"): void {
  if (typeof config === "string") { assertSecretReferenceAllowed(config, field); return; }
  if (Array.isArray(config)) { for (const v of config) assertConfigurationSecretReferences(v, field); return; }
  if (typeof config === "object" && config !== null) {
    for (const v of Object.values(config as Record<string, unknown>)) assertConfigurationSecretReferences(v, field);
  }
}
