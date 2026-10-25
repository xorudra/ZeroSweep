import {
  BadRequestException, Body, Controller, Get, Inject, Param, Post, Req,
} from "@nestjs/common";
import { z } from "zod";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { ValidationWorkflowService } from "./workflows/validation-workflow.service";
import { ManualValidationService } from "./manual/manual-validation.service";

const validateSchema = z.object({
  validatorSlug: z.string().min(1).max(128).optional(),
  technique: z.string().min(1).max(128).optional(),
  reason: z.string().max(2000).optional(),
  parameters: z.record(z.union([z.string().max(512), z.number(), z.boolean()])).optional(),
  idempotencyKey: z.string().min(1).max(128).optional(),
  allowDuplicate: z.boolean().optional(),
  environment: z.enum(["PRODUCTION", "LAB"]).optional(),
}).strict();

const manualSchema = z.object({
  description: z.string().min(1).max(20000),
  outcome: z.enum(["VERIFIED", "NOT_REPRODUCED", "INCONCLUSIVE"]).optional(),
  evidence: z.record(z.unknown()).optional(),
  notes: z.string().max(20000).optional(),
}).strict();

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body ?? {});
  if (!result.success) {
    throw new BadRequestException(`invalid request: ${result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  }
  return result.data;
}

/**
 * Finding-scoped validation endpoints (Prompt 16 §78/§58):
 * POST /findings/:id/validate starts the governed workflow for the
 * finding; POST /findings/:id/manual-validation attaches analyst
 * evidence (§32) — ZeroSweep executes nothing for manual records.
 */
@Controller("findings")
export class FindingsValidationController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly workflows: ValidationWorkflowService,
    private readonly manual: ManualValidationService,
  ) {}

  private async ws(req: { headers: Record<string, unknown> }, user: RequestUser) {
    return resolveWorkspace(this.prisma, user, req.headers["x-workspace-id"] as string | undefined);
  }

  @Post(":id/validate")
  async validateFinding(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const input = parse(validateSchema, body);
    return this.workflows.createValidation(user, ws.id, { ...input, findingId: id });
  }

  @Post(":id/manual-validation")
  async addManualValidation(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const input = parse(manualSchema, body);
    return this.manual.addManualValidation(user, ws.id, id, input);
  }

  /** §53: the finding's validation history. */
  @Get(":id/validations")
  async listValidations(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.workflows.listForFinding(ws.id, id);
  }

  @Get(":id/manual-validations")
  async listManualValidations(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.manual.listForFinding(user, ws.id, id);
  }
}
