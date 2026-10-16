import { Injectable } from "@nestjs/common";
import { loadEnv, resolveTenantEnvSecret } from "@dsrclone/config";

/**
 * Secret REFERENCES (§48/§67): the database stores only reference names.
 * Resolution understands `env:<VAR>` references against the process
 * environment (injected by the deployment's secret manager). Any other
 * reference is unresolvable here and the dependent feature honestly
 * reports NOT_CONFIGURED — secrets themselves never live in the DB.
 *
 * Tenant-controlled references resolve ONLY operator-provisioned tenant
 * slots (`env:TENANT_SECRET_<SLOT>`): the resolver is the last trusted
 * decision point, so a tenant can never name a platform variable
 * (JWT_SECRET, DATABASE_URL, provider keys, …) and have its value —
 * or an HMAC derived from it — sent to a tenant-controlled destination
 * (security audit 2026-10-16, critical env-secret exfiltration).
 */
@Injectable()
export class SecretResolver {
  resolve(reference: string | null | undefined): string | null {
    return resolveTenantEnvSecret(reference);
  }

  /** Platform encryption key material for TOTP secrets (§27): held outside
   *  the database; in this deployment it derives from the server-side
   *  platform secret (KMS-held in production topologies). This is a
   *  server-side-only path — it never resolves a tenant-supplied name. */
  platformKeyMaterial(): string {
    return loadEnv().JWT_SECRET;
  }
}
