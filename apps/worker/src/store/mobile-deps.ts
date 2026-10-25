/**
 * Prompt 17 — Prisma-backed MobileConnectorDeps (§13/§58/§64).
 *
 * The registry resolves REGISTERED applications + builds from the
 * MobileApplication / MobileBuild rows (the build's artifact hash is
 * its identity, §5). Transports are deliberately UNWIRED in this
 * build: no MobSF instance client, no device-lab transport and no
 * proxy session reader is provisioned on the worker, so the MobSF
 * connector, the ADB lab adapter and the mitmproxy adapter report
 * NOT_CONFIGURED honestly at execute time — the executor gates already
 * refuse runs without a registered instance / approved session, and
 * nothing is ever fabricated. Provisioning a transport is a deployment
 * step (build-side), exactly like the P14 provider and P15 directory
 * transports.
 */
import { prisma } from "@zerosweep/database";
import type { MobileApplicationRecord, MobileBuildRecord, MobileConnectorDeps } from "@zerosweep/security-sdk";

function toApplicationRecord(app: {
  id: string; workspaceId: string; name: string; platform: string;
  packageName: string | null; bundleId: string | null;
  environment: string; criticality: string; status: string;
}): MobileApplicationRecord {
  return {
    id: app.id, workspaceId: app.workspaceId, name: app.name,
    platform: app.platform as MobileApplicationRecord["platform"],
    ...(app.packageName ? { packageName: app.packageName } : {}),
    ...(app.bundleId ? { bundleId: app.bundleId } : {}),
    environment: app.environment, criticality: app.criticality, status: app.status,
  };
}

function toBuildRecord(build: {
  id: string; applicationId: string; workspaceId: string;
  versionName: string | null; versionCode: number | null;
  artifactHash: string; artifactFormat: string; artifactReference: string | null;
  analysisArtifacts: unknown;
}): MobileBuildRecord {
  return {
    id: build.id, applicationId: build.applicationId, workspaceId: build.workspaceId,
    ...(build.versionName ? { versionName: build.versionName } : {}),
    ...(build.versionCode !== null ? { versionCode: build.versionCode } : {}),
    artifactHash: build.artifactHash,
    artifactFormat: build.artifactFormat as MobileBuildRecord["artifactFormat"],
    ...(build.artifactReference ? { artifactReference: build.artifactReference } : {}),
    ...((build.analysisArtifacts as Record<string, unknown> | null) ? { analysisArtifacts: build.analysisArtifacts as Record<string, unknown> } : {}),
  };
}

export function prismaMobileDeps(): MobileConnectorDeps {
  return {
    applications: {
      async getApplication(id: string) {
        const app = await prisma.mobileApplication.findUnique({ where: { id } });
        return app ? toApplicationRecord(app) : undefined;
      },
      async getBuild(id: string) {
        const build = await prisma.mobileBuild.findUnique({ where: { id } });
        return build ? toBuildRecord(build) : undefined;
      },
      async getLatestBuild(applicationId: string) {
        const build = await prisma.mobileBuild.findFirst({
          where: { applicationId }, orderBy: { createdAt: "desc" },
        });
        return build ? toBuildRecord(build) : undefined;
      },
    },
    // No transports wired (see header): every entry point that needs
    // one fails closed as NOT_CONFIGURED inside the adapters.
    transports: {},
  };
}
