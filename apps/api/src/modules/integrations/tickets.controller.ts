import { Body, Controller, Get, Inject, Param, Post } from "@nestjs/common";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { createTicketSchema, resolveConflictSchema } from "./dto/schemas";
import { TicketsService } from "./tickets/tickets.service";

/**
 * Remediation ticket API (Prompt 24 §107): the ticket list the
 * /remediation/tickets page renders, ticket creation from a finding,
 * manual sync, and conflict resolution.
 */
@Controller()
export class TicketsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly tickets: TicketsService,
  ) {}

  @Get("remediation/tickets")
  async list(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.tickets.listTickets(user, ws.id);
  }

  @Post("findings/:id/tickets")
  async create(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.tickets.createTicketForFinding(user, ws.id, id, parseOrThrow(createTicketSchema, body ?? {}));
  }

  @Post("remediation/tickets/:id/sync")
  async sync(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.tickets.syncTicket(user, ws.id, id);
  }

  @Post("remediation/ticket-conflicts/:id/resolve")
  async resolve(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.tickets.resolveConflict(user, ws.id, id, parseOrThrow(resolveConflictSchema, body ?? {}));
  }
}
