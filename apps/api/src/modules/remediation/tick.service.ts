import { Injectable } from "@nestjs/common";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { RemediationSlaService } from "./sla.service";
import { RemediationExceptionsService } from "./exceptions.service";
import { RemediationRegressionService } from "./regression.service";
import { RemediationTicketsService } from "./tickets.service";

/**
 * The remediation tick (Prompt 31 §26/§47/§82/§72): one operator pass
 * that evaluates SLA states, expires exceptions, syncs tickets and
 * scans for regressions. Exposed as an authenticated endpoint so the
 * P22 scheduler (or an operator) drives it — every sub-pass records
 * its own audit/outbox events, and delivery honesty is inherited from
 * the router/connectors.
 */
@Injectable()
export class RemediationTickService {
  constructor(
    private readonly sla: RemediationSlaService,
    private readonly exceptions: RemediationExceptionsService,
    private readonly regressions: RemediationRegressionService,
    private readonly tickets: RemediationTicketsService,
  ) {}

  async tick(user: RequestUser, workspaceId: string, now = new Date()) {
    const sla = await this.sla.evaluateWorkspace(user, workspaceId, now);
    const exceptions = await this.exceptions.sweepExpiries(user, workspaceId, now);
    const tickets = await this.tickets.syncWorkspace(user, workspaceId, now);
    const regressions = await this.regressions.detectRegressions(user, workspaceId, now);
    return { sla, exceptions, tickets, regressions, at: now };
  }
}
