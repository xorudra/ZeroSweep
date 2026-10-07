/**
 * Prompt 18 — Prisma-backed BinaryConnectorDeps (§36–§39).
 *
 * The registry resolves REGISTERED artifacts from the BinaryArtifact
 * rows (the artifact's SHA-256 is its identity, §3). Transports are
 * deliberately UNWIRED in this build: no IDA or Binary Ninja
 * installation is provisioned on the worker, so the commercial
 * connectors honestly report NOT_INSTALLED / NOT_CONFIGURED and the
 * baseline open-source pipeline is unaffected (§96). Provisioning a
 * licensed installation is a deployment step (build-side), exactly
 * like the P14 provider and P15 directory transports.
 */
import { prisma } from "@dsrclone/database";
import type { BinaryArtifactRecord, BinaryConnectorDeps } from "@dsrclone/security-sdk";

function toArtifactRecord(row: {
  id: string; workspaceId: string; name: string; source: string;
  artifactReference: string | null; sha256: string; sha1: string | null;
  sizeBytes: bigint; format: string; analysisArtifacts: unknown; status: string;
}): BinaryArtifactRecord {
  return {
    id: row.id, workspaceId: row.workspaceId, name: row.name,
    source: row.source as BinaryArtifactRecord["source"],
    ...(row.artifactReference ? { artifactReference: row.artifactReference } : {}),
    sha256: row.sha256,
    ...(row.sha1 ? { sha1: row.sha1 } : {}),
    sizeBytes: Number(row.sizeBytes),
    format: row.format,
    ...((row.analysisArtifacts as Record<string, unknown> | null) ? { analysisArtifacts: row.analysisArtifacts as Record<string, unknown> } : {}),
    status: row.status,
  };
}

export function prismaBinaryDeps(): BinaryConnectorDeps {
  return {
    artifacts: {
      async getArtifact(id: string) {
        const row = await prisma.binaryArtifact.findUnique({ where: { id } });
        return row ? toArtifactRecord(row) : undefined;
      },
      async getArtifactByHash(workspaceId: string, sha256: string) {
        const row = await prisma.binaryArtifact.findFirst({ where: { workspaceId, sha256 } });
        return row ? toArtifactRecord(row) : undefined;
      },
    },
    // No transports wired (see header): the commercial connectors
    // report their honest uninstalled states, never data.
    transports: {},
  };
}
