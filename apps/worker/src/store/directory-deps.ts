import { prisma } from "@dsrclone/database";
import type { DirectoryConnectorDeps } from "@dsrclone/security-sdk";

/**
 * Prisma-backed directory connector dependencies (Prompt 15 §7/§15).
 * Domain resolution reads the registered ActiveDirectoryDomain row +
 * its credential profile (REFERENCE name only — the value never
 * reaches the worker).
 *
 * TRANSPORTS ARE DELIBERATELY EMPTY: live read-only LDAP/BloodHound
 * transports are wired only inside an APPROVED internal
 * DIRECTORY_ANALYSIS worker (§10/§11) at deployment time. Until then
 * the connectors honestly report NOT_CONFIGURED and never fabricate
 * directory data (§89/§105 discipline, mirroring Prompt 14).
 */
export function prismaDirectoryDeps(): DirectoryConnectorDeps {
  return {
    domains: {
      async getDomain(domainId: string) {
        const domain = await prisma.activeDirectoryDomain.findUnique({
          where: { id: domainId },
          include: {
            credentialProfile: true,
            controllers: { select: { hostname: true, dnsName: true } },
          },
        });
        if (!domain) return undefined;
        return {
          id: domain.id,
          workspaceId: domain.workspaceId,
          dnsName: domain.dnsName,
          ...(domain.netbiosName ? { netbiosName: domain.netbiosName } : {}),
          ...(domain.domainSid ? { domainSid: domain.domainSid } : {}),
          status: domain.status,
          ...(domain.credentialProfile?.credentialReference
            ? { credentialReference: domain.credentialProfile.credentialReference }
            : {}),
          ...(domain.credentialProfile?.identityKind
            ? { identityKind: domain.credentialProfile.identityKind }
            : {}),
          dcHosts: domain.controllers.map((c) => c.dnsName ?? c.hostname),
        };
      },
    },
    transports: {},
  };
}
