import { Inject, Injectable } from "@nestjs/common";
import { socAlertFingerprint } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AlertService } from "../alerts/alert.service";
import type { Row } from "../helpers";

/**
 * SOC correlation (Prompt 28 §70–§72). This layer REUSES the
 * Prompt 27 correlation engine's signals — it does not build a
 * second graph/correlation system (§70). It adds the SOC-specific
 * composite patterns of §71 on top of fresh telemetry, evaluating
 * each pattern against real platform rows (assets, findings, KEV
 * records, P27 signals) and raising alerts through the one alert
 * path, with the pattern evidence recorded in the alert.
 */
@Injectable()
export class SocCorrelationService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly alerts: AlertService,
  ) {}

  private async assetContext(workspaceId: string, assetId?: string): Promise<Row | null> {
    if (!assetId) return null;
    return (await this.prisma.asset.findFirst({ where: { id: assetId, workspaceId } }).catch(() => null)) as Row | null;
  }

  async evaluateEventPatterns(organizationId: string, workspaceId: string, eventRow: Row): Promise<{ alertsCreated: number; patterns: string[] }> {
    const attributes = (eventRow.attributes as Record<string, unknown>) ?? {};
    const fired: string[] = [];
    let alertsCreated = 0;
    const asset = await this.assetContext(workspaceId, eventRow.assetId as string | undefined);
    const raise = async (pattern: string, title: string, description: string, severity: string, extra: {
      kev?: boolean; threatIntelConfidence?: number;
    }) => {
      const fingerprint = socAlertFingerprint({
        ruleId: `soc-pattern:${pattern}`, ruleVersion: 1,
        assetId: eventRow.assetId as string | undefined,
        identityReference: eventRow.identityReference as string | undefined,
      });
      const raised = await this.alerts.raiseAlert({
        organizationId, workspaceId, fingerprint, title, description, severity,
        source: "CORRELATION", assetId: eventRow.assetId as string | undefined,
        identityReference: eventRow.identityReference as string | undefined,
        assetCriticality: asset?.criticality as string | undefined,
        internetExposed: attributes.public === true, kev: extra.kev,
        threatIntelConfidence: extra.threatIntelConfidence,
        correlationSignalCount: 1, confidence: "MEDIUM",
      });
      if (raised.created) alertsCreated++;
      fired.push(pattern);
    };

    // §71: authentication anomaly + privileged identity.
    if (eventRow.eventCategory === "AUTHENTICATION" && attributes.unexpected === true && attributes.privileged === true) {
      await raise("auth-anomaly-privileged", "Authentication anomaly on a privileged identity",
        `Unexpected authentication context for privileged identity ${eventRow.identityReference ?? "unknown"}.`, "HIGH", {});
    }

    // §71: public exposure + KEV (a KEV finding exists on the asset).
    if (eventRow.eventAction === "EXPOSURE_CHANGED" && attributes.public === true && eventRow.assetId) {
      const findings = await this.prisma.finding.findMany({
        where: { workspaceId, assetId: eventRow.assetId as string },
      }).catch(() => []);
      let kev = false;
      for (const finding of findings as Row[]) {
        const cve = (finding.cveId as string) ?? (finding.cve as string);
        if (!cve) continue;
        const kevRecord = await this.prisma.kevRecord.findFirst({ where: { cveId: cve } }).catch(() => null);
        if (kevRecord) { kev = true; break; }
      }
      if (kev) {
        await raise("public-exposure-kev", "Public exposure change on an asset with a KEV finding",
          "The asset became publicly exposed while carrying a finding whose CVE is in the CISA KEV catalog.", "CRITICAL", { kev: true });
      }
    }

    // §71: secret exposure + repository event.
    if (eventRow.eventAction === "SECRET_DETECTED" && (attributes.repositoryId || attributes.repository)) {
      await raise("secret-exposure-repository", "Secret exposure linked to a repository event",
        "A secret detection event is linked to a repository — rotation and history review are required.", "HIGH", {});
    }

    // §71: control failure + existing security alert on the same asset.
    if (eventRow.eventAction === "CONTROL_DISABLED" && eventRow.assetId) {
      const open = await this.prisma.securityAlert.findFirst({
        where: { workspaceId, assetId: eventRow.assetId as string, status: { in: ["NEW", "TRIAGED", "INVESTIGATING"] } },
      }).catch(() => null);
      if (open) {
        await raise("control-failure-with-alert", "Security control disabled on an asset with an open alert",
          `A control was disabled on an asset that already has open alert ${(open as Row).id}.`, "HIGH", {});
      }
    }

    // §71: indicator match + critical asset — evaluated from the
    // IndicatorMatch rows the intel matcher just wrote for this event.
    if (eventRow.id) {
      const match = await this.prisma.indicatorMatch.findFirst({
        where: { workspaceId, telemetryEventId: eventRow.id as string },
      }).catch(() => null);
      if (match && asset?.criticality === "CRITICAL") {
        await raise("indicator-match-critical-asset", "Indicator match on a critical asset",
          `Telemetry on a CRITICAL asset matched threat indicator ${(match as Row).indicatorId} (confidence ${(match as Row).confidence}).`,
          "HIGH", { threatIntelConfidence: (match as Row).confidence as number });
      }
    }
    return { alertsCreated, patterns: fired };
  }

  /** §70: surface Prompt 27 correlation signals into the SOC view —
   *  read-through, no second correlation store. */
  async listPlatformSignals(workspaceId: string, limit = 100) {
    const items = await this.prisma.securityCorrelationSignal.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: Math.min(limit, 500),
    }).catch(() => []);
    return { items, total: (items as Row[]).length, source: "Prompt 27 SecurityCorrelationSignal (reused, §70)" };
  }
}
