import { Controller, Get, Query } from "@nestjs/common";
import { paginationSchema } from "@dsrclone/validation";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { AuditService } from "./audit.service";

@Controller("audit-logs")
export class AuditController {
  constructor(private readonly audit: AuditService) {}
  @Get()
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER")
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const { page = 1, pageSize = 20 } = parseOrThrow(paginationSchema, query);
    return this.audit.list(user.organizationId, page, pageSize);
  }
}
