import { prisma } from "@dsrclone/database";
import type { CloudConnectorDeps } from "@dsrclone/security-sdk";

/**
 * Prisma-backed cloud connector dependencies for the production
 * worker (Prompt 14 §9/§10): account records resolve from the
 * CloudAccount table — credential REFERENCE only; no secret value is
 * ever loaded into a record, a log line or a queue payload.
 *
 * Provider API transports are provisioned per deployment on
 * CLOUD_ANALYSIS workers (read-only SDK clients resolving the secret
 * reference inside the worker boundary, §11). Until a transport is
 * wired on a worker, `transports` stays empty and accounts honestly
 * report NOT_CONFIGURED — inventory is never fabricated (§9).
 */
export function prismaCloudDeps(): CloudConnectorDeps {
  return {
    accounts: {
      async getById(id: string) {
        const row = await prisma.cloudAccount.findUnique({ where: { id } });
        if (!row) return null;
        return {
          id: row.id,
          provider: row.provider as "AWS" | "AZURE" | "GCP",
          name: row.name,
          externalAccountId: row.externalAccountId,
          ...(row.environment ? { environment: row.environment } : {}),
          ...(row.criticality ? { criticality: row.criticality } : {}),
          ...(row.credentialReference ? { credentialReference: row.credentialReference } : {}),
        };
      },
    },
    transports: {},
  };
}
