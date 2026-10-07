import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { SecurityValidationController } from "./security-validation.controller";
import { FindingsValidationController } from "./findings-validation.controller";
import { ValidationWorkflowService } from "./workflows/validation-workflow.service";
import { ValidationApprovalsService } from "./approvals/approvals.service";
import { ValidationEvidenceService } from "./evidence/evidence.service";
import { ValidationSessionsService } from "./sessions/sessions.service";
import { ValidationPoliciesService } from "./policies/policies.service";
import { KillSwitchService } from "./safety/kill-switch.service";
import { ValidationCallbackService } from "./callbacks/callback.service";
import { ManualValidationService } from "./manual/manual-validation.service";
import { ValidationReportsService } from "./reports/validation-reports.service";

/**
 * Controlled security validation (Prompt 16 §2). The API plans,
 * approves and records — it never executes a validator (§45); sessions
 * run in isolated workers via the ValidationRunner.
 */
@Module({
  imports: [AuditModule],
  controllers: [SecurityValidationController, FindingsValidationController],
  providers: [
    ValidationWorkflowService,
    ValidationApprovalsService,
    ValidationEvidenceService,
    ValidationSessionsService,
    ValidationPoliciesService,
    KillSwitchService,
    ValidationCallbackService,
    ManualValidationService,
    ValidationReportsService,
  ],
  exports: [ValidationWorkflowService],
})
export class SecurityValidationModule {}
