import { prisma } from "@dsrclone/database";
import {
  AdapterUnavailableError, type KubernetesConnectorDeps,
} from "@dsrclone/security-sdk";

/**
 * Prisma-backed Kubernetes connector dependencies for the production
 * worker (Prompt 13 §32–§34): cluster records resolve from the
 * KubernetesCluster table — API server REFERENCE + credential
 * REFERENCE only; no kubeconfig or token value is ever loaded into a
 * record, a log line or a queue payload.
 *
 * The live cluster API transport is provisioned per deployment (a
 * read-only client for the registered service account, §82 bounded
 * access policy). Until a transport is wired on a worker, inventory
 * honestly reports UNAVAILABLE — the connector never invents cluster
 * state (§34).
 */
export function prismaKubernetesDeps(): KubernetesConnectorDeps {
  return {
    clusters: {
      async getById(id: string) {
        const row = await prisma.kubernetesCluster.findUnique({ where: { id } });
        if (!row) return null;
        return {
          id: row.id,
          name: row.name,
          apiServerReference: row.apiServerReference,
          ...(row.credentialReference ? { credentialReference: row.credentialReference } : {}),
          ...(row.version ? { version: row.version } : {}),
        };
      },
    },
    transport: {
      async inventory() {
        throw new AdapterUnavailableError(
          "kubernetes: cluster API transport is not provisioned on this worker — inventory is UNAVAILABLE rather than fabricated (§34)",
        );
      },
    },
  };
}
