import { ConflictException, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcryptjs";
import { loginSchema, registerSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { parseOrThrow } from "../../common/parse";
import { AuditService } from "../audit/audit.service";

@Injectable()
export class AuthService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
  ) {}

  /** Registration creates the user + their first organization, OWNER membership
   *  and a default workspace — the multi-tenant root. Passwords are bcrypt-hashed. */
  async register(raw: unknown) {
    const data = parseOrThrow(registerSchema, raw);
    const existing = await this.prisma.user.findUnique({ where: { email: data.email } });
    if (existing) throw new ConflictException("An account with this email already exists");
    const passwordHash = await bcrypt.hash(data.password, 12);
    const slug = data.organizationName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + "-" + Math.random().toString(36).slice(2, 8);
    const user = await this.prisma.user.create({ data: { email: data.email, name: data.name, passwordHash } });
    const org = await this.prisma.organization.create({ data: { name: data.organizationName, slug } });
    await this.prisma.membership.create({ data: { userId: user.id, organizationId: org.id, role: "OWNER" } });
    const workspace = await this.prisma.workspace.create({ data: { organizationId: org.id, name: "Default Workspace" } });
    await this.audit.record({ actorId: user.id, organizationId: org.id, workspaceId: workspace.id, action: "REGISTER", resourceType: "User", resourceId: user.id });
    return { user: { id: user.id, email: user.email, name: user.name }, organization: org, workspace, ...this.issueToken(user.id, user.email, org.id, "OWNER") };
  }

  async login(raw: unknown) {
    const data = parseOrThrow(loginSchema, raw);
    const user = await this.prisma.user.findUnique({ where: { email: data.email }, include: { memberships: { where: { status: "ACTIVE" }, take: 1 } } });
    if (!user || !user.isActive || !(await bcrypt.compare(data.password, user.passwordHash))) {
      throw new UnauthorizedException("Invalid email or password");
    }
    const membership = user.memberships[0];
    if (!membership) throw new UnauthorizedException("User has no active organization membership");
    await this.audit.record({ actorId: user.id, organizationId: membership.organizationId, action: "LOGIN", resourceType: "User", resourceId: user.id });
    return { user: { id: user.id, email: user.email, name: user.name }, ...this.issueToken(user.id, user.email, membership.organizationId, membership.role) };
  }

  private issueToken(sub: string, email: string, organizationId: string, role: string) {
    return { accessToken: this.jwt.sign({ sub, email, organizationId, role }) };
  }
}
