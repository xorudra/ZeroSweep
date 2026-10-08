import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { GrcController } from "./grc.controller";
import { FrameworkService } from "./frameworks/framework.service";
import { ControlService } from "./controls/control.service";
import { EvidenceService } from "./evidence/evidence.service";
import { MonitoringService } from "./monitoring/monitoring.service";
import { AssessmentService } from "./assessments/assessment.service";
import { RiskService } from "./risks/risk.service";
import { PolicyService } from "./policies/policy.service";
import { GrcAuditService } from "./audits/audit.service";
import { VendorService } from "./vendors/vendor.service";
import { FindingLinkService } from "./findings/finding-link.service";
import { GrcAnalyticsService } from "./analytics/analytics.service";
import { GrcReportService } from "./reports/report.service";
import { GrcBackupService } from "./reports/backup.service";
import { AiGrcService } from "./ai/ai-grc.service";

/**
 * Prompt 26 — Enterprise Compliance, Governance, Risk & Audit (GRC)
 * Engine. Layers over the existing platform (findings, posture,
 * identity, scheduler, audit log) — it creates NO duplicate
 * vulnerability-management or audit-log system (§2).
 */
@Module({
  imports: [AuditModule],
  controllers: [GrcController],
  providers: [
    FrameworkService, ControlService, EvidenceService, MonitoringService,
    AssessmentService, RiskService, PolicyService, GrcAuditService,
    VendorService, FindingLinkService, GrcAnalyticsService, GrcReportService,
    GrcBackupService, AiGrcService,
  ],
  exports: [MonitoringService, EvidenceService, RiskService],
})
export class GrcModule {}
