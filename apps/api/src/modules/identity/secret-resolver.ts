import { Injectable } from "@nestjs/common";
import { loadEnv } from "@dsrclone/config";

/**
 * Secret REFERENCES (§48/§67): the database stores only reference names.
 * Resolution understands `env:<VAR>` references against the process
 * environment (injected by the deployment's secret manager). Any other
 * reference is unresolvable here and the dependent feature honestly
 * reports NOT_CONFIGURED — secrets themselves never live in the DB.
 */
@Injectable()
export class SecretResolver {
  resolve(reference: string | null | undefined): string | null {
    if (!reference) return null;
    if (reference.startsWith("env:")) {
      const name = reference.slice(4);
      return process.env[name] ?? null;
    }
    return null;
  }

  /** Platform encryption key material for TOTP secrets (§27): held outside
   *  the database; in this deployment it derives from the server-side
   *  platform secret (KMS-held in production topologies). */
  platformKeyMaterial(): string {
    return loadEnv().JWT_SECRET;
  }
}
