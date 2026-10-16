import { Body, Controller, Delete, Get, Headers, Param, Patch, Post, Req, Res, UnauthorizedException } from "@nestjs/common";
import type { Request, Response } from "express";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { applySessionCookie, clearSessionCookie, readSessionCookie, setSessionCookie, withoutSessionToken } from "../../common/session-cookie";
import { requireIdentityPermission } from "./permissions";
import { AuthFlowService } from "./auth-flow.service";
import { MfaService } from "./mfa/mfa.service";
import { WebAuthnService } from "./webauthn/webauthn.service";
import { SessionsService } from "./sessions/sessions.service";
import { SsoService } from "./sso/sso.service";
import { ScimService } from "./scim/scim.service";
import { KeysService } from "./keys/keys.service";
import { GovernanceService } from "./governance/governance.service";
import { GENERIC_RESET_MESSAGE, randomToken, sha256Hex } from "@dsrclone/security-sdk";
import { Inject } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuthService } from "../auth/auth.service";

/** Auth-surface extensions (§101): MFA challenge/verify, passkeys, device
 *  sessions, password reset/change. Login itself stays in AuthController. */
@Controller("auth")
export class IdentityAuthController {
  constructor(
    private readonly flow: AuthFlowService,
    private readonly mfa: MfaService,
    private readonly webauthn: WebAuthnService,
    private readonly sessions: SessionsService,
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly auth: AuthService,
  ) {}

  @Public()
  @Post("mfa/challenge")
  async rotateChallenge(@Body() body: { challengeToken: string }) {
    // Re-issue a fresh challenge for an in-flight MFA login (old one dies).
    // Rotation must NOT reset the login's security budget: an expired
    // challenge stays dead and the 5-attempt bound + original expiry are
    // inherited by the replacement, so total MFA guesses per login stay
    // bounded at 5 within the original 10-minute window.
    const existing = await this.prisma.authChallenge.findUnique({ where: { tokenHash: sha256Hex(body.challengeToken) } });
    if (!existing || existing.type !== "MFA_TOTP" || existing.consumedAt) return { challengeToken: null };
    if (new Date(existing.expiresAt as Date).getTime() <= Date.now()) return { challengeToken: null };
    if (((existing.attempts as number) ?? 0) >= 5) return { challengeToken: null };
    // Atomic consume (security audit 2026-10-16 run-4): exactly one of
    // any concurrent rotations wins the CAS and mints the replacement;
    // the losers see the challenge already consumed and mint nothing, so
    // the login's remaining budget can never be duplicated by racing.
    const consumed = await this.prisma.authChallenge.updateMany({
      where: { id: existing.id, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    if (consumed.count === 0) return { challengeToken: null };
    // Inherit the POST-CAS attempts (security audit 2026-10-16 run-5):
    // verify claims that landed between the snapshot read and the CAS
    // must stay spent. After consumption no further claim can land
    // (claims require consumedAt: null), so this re-read is final.
    const current = await this.prisma.authChallenge.findUnique({ where: { id: existing.id } });
    const inheritedAttempts = ((current?.attempts as number) ?? (existing.attempts as number) ?? 0);
    const challengeToken = randomToken(32);
    await this.prisma.authChallenge.create({
      data: { userId: existing.userId, type: "MFA_TOTP", tokenHash: sha256Hex(challengeToken), expiresAt: new Date(existing.expiresAt as Date), attempts: inheritedAttempts as never, metadata: existing.metadata as never },
    });
    return { challengeToken };
  }

  @Public()
  @Post("mfa/enroll-challenge")
  async enrollChallenge(@Body() body: { challengeToken: string }) {
    return this.flow.enrollViaChallenge(body.challengeToken);
  }

  @Public()
  @Post("mfa/verify")
  async verifyMfa(@Body() body: { challengeToken: string; code?: string; recoveryCode?: string }, @Res({ passthrough: true }) res: Response) {
    const result = await this.flow.verifyMfaChallenge(body.challengeToken, body);
    applySessionCookie(res, result);
    return withoutSessionToken(result);
  }

  @Post("mfa/enroll")
  async enroll(@CurrentUser() user: RequestUser) { return this.mfa.enrollTotp(user); }

  @Post("mfa/activate")
  async activate(@CurrentUser() user: RequestUser, @Body() body: { code: string }) { return this.mfa.activateTotp(user, body.code); }

  @Get("mfa/status")
  async status(@CurrentUser() user: RequestUser) { return this.mfa.status(user.id); }

  @Post("mfa/recovery-codes")
  async recoveryCodes(@CurrentUser() user: RequestUser) { return this.mfa.generateRecoveryCodes(user); }

  @Post("mfa/step-up")
  async stepUp(@CurrentUser() user: RequestUser, @Body() body: { sessionId: string; code: string }) {
    return this.flow.stepUp(user, body);
  }

  @Post("mfa/reset")
  async resetMfa(@CurrentUser() user: RequestUser, @Body() body: { userId: string }) {
    requireIdentityPermission(user, "MANAGE_SECURITY_POLICY");
    return this.mfa.adminResetMfa(user, body.userId);
  }

  @Get("passkeys")
  async passkeys(@CurrentUser() user: RequestUser) { return this.webauthn.listCredentials(user); }

  @Delete("passkeys/:id")
  async removePasskey(@CurrentUser() user: RequestUser, @Param("id") id: string) { return this.webauthn.removeCredential(user, id); }

  @Post("passkeys/register/options")
  async passkeyOptions(@CurrentUser() user: RequestUser) { return this.webauthn.registrationOptions(user); }

  @Post("passkeys/register")
  async passkeyRegister(@CurrentUser() user: RequestUser, @Body() body: never) { return this.webauthn.register(user, body); }

  @Public()
  @Post("passkeys/authenticate/options")
  async passkeyAuthOptions(@Body() body: { email: string }) {
    const user = await this.prisma.user.findUnique({ where: { email: body.email } });
    // Identical response shape whether or not the account exists (§109).
    if (!user) return { challenge: randomToken(32), allowCredentials: [] as string[] };
    return this.webauthn.authenticationOptions(user.id as string);
  }

  @Public()
  @Post("passkeys/authenticate")
  async passkeyAuthenticate(@Body() body: { email: string; challenge: string; credentialId: string; authenticatorData: string; clientDataJSON: string; signature: string }, @Res({ passthrough: true }) res: Response) {
    const user = await this.prisma.user.findUnique({ where: { email: body.email }, include: { memberships: { where: { status: "ACTIVE" }, take: 1 } } });
    if (!user || !user.memberships[0]) return { authenticated: false };
    const ok = await this.webauthn.authenticate(user.id as string, user.memberships[0].organizationId as string, body);
    if (!ok) return { authenticated: false };
    const login = await this.auth.completeLogin(user, user.memberships[0], "unknown", false, "PHISHING_RESISTANT");
    const result = { authenticated: true, ...login };
    applySessionCookie(res, result);
    return withoutSessionToken(result);
  }

  @Get("sessions")
  async listSessions(@CurrentUser() user: RequestUser, @Headers("x-session-id") sessionId?: string) {
    return this.sessions.listSessions(user.id, sessionId);
  }

  @Delete("sessions/:id")
  async revokeSession(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.sessions.revokeSession({ id: user.id, email: user.email, organizationId: user.organizationId, role: user.role }, id);
  }

  @Delete("sessions")
  async revokeAll(@CurrentUser() user: RequestUser) {
    return this.sessions.revokeAllSessions({ id: user.id, email: user.email, organizationId: user.organizationId, role: user.role }, user.id);
  }

  /** Launch Safety A7 — refresh: exchange the HttpOnly session cookie
   *  for a fresh access JWT. The presented credential is validated under
   *  the standard session rules, then ROTATED: the old cookie token dies
   *  and only the token in the response's Set-Cookie can refresh again.
   *  The new JWT keeps the same `sid` — the session itself lives on. */
  @Public()
  @Post("refresh")
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const presented = readSessionCookie(req);
    if (!presented) throw new UnauthorizedException("No session cookie");
    const ctx = await this.sessions.validateSessionToken(presented);
    const rotated = await this.sessions.rotateSessionCredential(ctx.sessionId, presented);
    const user = await this.prisma.user.findUnique({ where: { id: ctx.user.id } });
    const accessToken = this.auth.issueAccessToken({
      sub: ctx.user.id, email: ctx.user.email, name: (user?.name as string | undefined) ?? undefined,
      organizationId: ctx.user.organizationId, role: ctx.user.role,
      isPlatformAdmin: user?.isPlatformAdmin === true, sessionId: ctx.sessionId,
    });
    setSessionCookie(res, rotated.sessionToken);
    return { accessToken, sessionId: ctx.sessionId };
  }

  @Post("logout")
  async logout(@CurrentUser() user: RequestUser, @Body() body: { sessionId?: string }, @Res({ passthrough: true }) res: Response) {
    // A7: logout revokes the caller's own session — the one their JWT
    // names — by default (an explicit body.sessionId keeps the previous
    // behaviour). With the guard's session check, revoking it kills the
    // presented JWT and every other JWT minted for the session at once,
    // and the cleared cookie can no longer refresh.
    const sessionId = body?.sessionId ?? user.sessionId;
    if (sessionId) {
      await this.sessions.revokeSession({ id: user.id, email: user.email, organizationId: user.organizationId, role: user.role }, sessionId);
    }
    clearSessionCookie(res);
    return { loggedOut: true };
  }

  @Public()
  @Post("password-reset")
  async passwordReset(@Body() body: { email: string }) {
    await this.flow.requestPasswordReset(body.email);
    // The outward response never reveals whether the account exists (§109).
    return { message: GENERIC_RESET_MESSAGE };
  }

  @Public()
  @Post("password-reset/confirm")
  async passwordResetConfirm(@Body() body: { token: string; newPassword: string }) {
    return this.flow.resetPassword(body.token, body.newPassword);
  }

  @Post("password/change")
  async passwordChange(@CurrentUser() user: RequestUser, @Body() body: { currentPassword: string; newPassword: string; currentSessionId?: string }) {
    return this.flow.changePassword(user, body);
  }
}

/** Organization identity administration (§102–105): members, invitations,
 *  security + password policy, SSO, domains, SCIM admin, break-glass,
 *  access reviews, privileged report, observability. Every handler scopes
 *  to the caller's organization; foreign ids resolve to 404 (§141). */
@Controller("organizations")
export class IdentityOrganizationsController {
  constructor(
    private readonly governance: GovernanceService,
    private readonly sso: SsoService,
    private readonly scim: ScimService,
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
  ) {}

  @Get(":id")
  async getOrg(@CurrentUser() user: RequestUser, @Param("id") id: string) { return this.governance.getOrganization(user, id); }

  @Get(":id/members")
  async members(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    if (id !== user.organizationId) return [];
    return this.governance.listMembers(user);
  }

  @Patch(":id/members/:userId/role")
  async setRole(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("userId") userId: string, @Body() body: { role: string }) {
    requireIdentityPermission(user, "MANAGE_MEMBERS");
    if (id !== user.organizationId) return { updated: false };
    return this.governance.setMembershipRole(user, userId, body.role);
  }

  @Patch(":id/members/:userId/status")
  async setStatus(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("userId") userId: string, @Body() body: { status: string }) {
    requireIdentityPermission(user, "MANAGE_MEMBERS");
    if (id !== user.organizationId) return { updated: false };
    return this.governance.setMembershipStatus(user, userId, body.status);
  }

  @Post(":id/invitations")
  async invite(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_INVITATIONS");
    if (id !== user.organizationId) return { created: false };
    return this.governance.createInvitation(user, body);
  }

  @Get(":id/security-policy")
  async getPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return id === user.organizationId ? this.governance.getSecurityPolicy(user) : { organizationId: null };
  }

  @Patch(":id/security-policy")
  async updatePolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SECURITY_POLICY");
    if (id !== user.organizationId) return { updated: false };
    return this.governance.updateSecurityPolicy(user, body);
  }

  @Get(":id/password-policy")
  async getPasswordPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return id === user.organizationId ? this.governance.getPasswordPolicy(user) : { organizationId: null };
  }

  @Patch(":id/password-policy")
  async updatePasswordPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SECURITY_POLICY");
    if (id !== user.organizationId) return { updated: false };
    return this.governance.updatePasswordPolicy(user, body);
  }

  @Get(":id/sso")
  async listSso(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "MANAGE_SSO");
    return id === user.organizationId ? this.sso.listProviders(user) : [];
  }

  @Post(":id/sso")
  async createSso(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SSO");
    if (id !== user.organizationId) return { created: false };
    return this.sso.createProvider(user, body);
  }

  @Patch(":id/sso/:providerId")
  async updateSso(@CurrentUser() user: RequestUser, @Param("providerId") providerId: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SSO");
    return this.sso.updateProvider(user, providerId, body);
  }

  @Post(":id/sso/test")
  async testSso(@CurrentUser() user: RequestUser, @Body() body: { providerId: string }) {
    requireIdentityPermission(user, "MANAGE_SSO");
    return this.sso.testProvider(user, body.providerId);
  }

  @Post(":id/domains")
  async addDomain(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: { domain: string }) {
    requireIdentityPermission(user, "MANAGE_DOMAINS");
    if (id !== user.organizationId) return { created: false };
    return this.governance.startDomainVerification(user, body.domain);
  }

  @Get(":id/domains")
  async domains(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return id === user.organizationId ? this.governance.listDomains(user) : [];
  }

  @Post(":id/break-glass")
  async breakGlass(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: { userId: string }) {
    requireIdentityPermission(user, "MANAGE_BREAK_GLASS");
    if (id !== user.organizationId) return { enrolled: false };
    return this.sso.enrollBreakGlass(user, body.userId);
  }

  @Get(":id/scim")
  async scimStatus(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "MANAGE_SCIM");
    return id === user.organizationId ? this.scim.tokenStatus(id) : { configured: false };
  }

  @Post(":id/scim/token")
  async scimToken(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "MANAGE_SCIM");
    if (id !== user.organizationId) return { created: false };
    return this.scim.createOrRotateToken(id, user.id);
  }

  @Get(":id/scim/mappings")
  async scimMappings(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "MANAGE_SCIM");
    return id === user.organizationId ? this.scim.listMappings(id) : [];
  }

  @Post(":id/scim/mappings")
  async createMapping(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SCIM");
    if (id !== user.organizationId) return { created: false };
    return this.scim.createMapping(id, user.id, body);
  }

  @Get(":id/privileged-report")
  async privilegedReport(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "VIEW_PRIVILEGED_REPORT");
    return id === user.organizationId ? this.governance.privilegedAccessReport(user) : { privilegedMemberships: [] };
  }

  @Get(":id/auth-observability")
  async observability(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "VIEW_PRIVILEGED_REPORT");
    return id === user.organizationId ? this.governance.authObservability(user) : { loginSucceeded: 0 };
  }

  @Post(":id/access-reviews")
  async createReview(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_ACCESS_REVIEWS");
    if (id !== user.organizationId) return { created: false };
    return this.governance.createAccessReview(user, body);
  }

  @Get(":id/access-reviews")
  async reviews(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "MANAGE_ACCESS_REVIEWS");
    return id === user.organizationId ? this.governance.listAccessReviews(user) : [];
  }

  @Get(":id/access-reviews/:reviewId")
  async review(@CurrentUser() user: RequestUser, @Param("reviewId") reviewId: string) {
    requireIdentityPermission(user, "MANAGE_ACCESS_REVIEWS");
    return this.governance.getAccessReview(user, reviewId);
  }

  @Post(":id/access-reviews/:reviewId/items/:itemId/decide")
  async decide(@CurrentUser() user: RequestUser, @Param("reviewId") reviewId: string, @Param("itemId") itemId: string, @Body() body: { decision: string; newRole?: string }) {
    requireIdentityPermission(user, "MANAGE_ACCESS_REVIEWS");
    return this.governance.decideAccessReviewItem(user, reviewId, itemId, body.decision, body.newRole);
  }

  @Post(":id/access-reviews/:reviewId/complete")
  async completeReview(@CurrentUser() user: RequestUser, @Param("reviewId") reviewId: string) {
    requireIdentityPermission(user, "MANAGE_ACCESS_REVIEWS");
    return this.governance.completeAccessReview(user, reviewId);
  }
}

/** Invitation acceptance is token-bound and public (§63). */
@Controller("invitations")
export class InvitationsController {
  constructor(private readonly governance: GovernanceService) {}

  @Public()
  @Post("accept")
  async accept(@Body() body: { token: string; name?: string; password?: string }) {
    return this.governance.acceptInvitation(body.token, body);
  }
}

/** SSO protocol endpoints (§103): dedicated, public, provider-scoped. */
@Controller("auth/sso")
export class SsoController {
  constructor(private readonly sso: SsoService) {}

  @Public()
  @Get("oidc/:organizationId/:providerId/start")
  async oidcStart(@Param("organizationId") org: string, @Param("providerId") provider: string, @Body() body: { redirectUri: string }) {
    return this.sso.startOidcLogin(org, provider, body?.redirectUri ?? "");
  }

  @Public()
  @Post("oidc/:organizationId/:providerId/callback")
  async oidcCallback(@Param("organizationId") org: string, @Param("providerId") provider: string, @Body() body: { code: string; state: string; redirectUri: string }, @Res({ passthrough: true }) res: Response) {
    const result = await this.sso.oidcCallback(org, provider, body);
    applySessionCookie(res, result);
    return withoutSessionToken(result);
  }

  @Public()
  @Get("saml/:organizationId/:providerId/start")
  async samlStart(@Param("organizationId") org: string, @Param("providerId") provider: string) {
    return this.sso.startSamlLogin(org, provider);
  }

  @Public()
  @Post("saml/:organizationId/:providerId/acs")
  async samlAcs(@Param("organizationId") org: string, @Param("providerId") provider: string, @Body() body: { samlResponse: string; relayState?: string }, @Res({ passthrough: true }) res: Response) {
    const result = await this.sso.samlAcs(org, provider, body);
    applySessionCookie(res, result);
    return withoutSessionToken(result);
  }
}

/** SCIM 2.0 (§66): public routes, authenticated by the dedicated SCIM
 *  bearer token inside the service — never by user JWTs/API keys. */
@Controller("scim/v2")
export class ScimController {
  constructor(private readonly scim: ScimService) {}

  @Public()
  @Get("ServiceProviderConfig")
  config() {
    return { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], patch: { supported: true }, bulk: { supported: false }, filter: { supported: true, maxResults: 100 }, authenticationSchemes: [{ type: "oauthbearertoken", name: "SCIM bearer token" }] };
  }

  @Public()
  @Post("Users")
  async createUser(@Headers("authorization") auth: string, @Body() body: Record<string, unknown>) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.createUser(organizationId, body);
  }

  @Public()
  @Get("Users")
  async listUsers(@Headers("authorization") auth: string, @Body() body: { filter?: string }) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.listUsers(organizationId, body?.filter);
  }

  @Public()
  @Get("Users/:id")
  async getUser(@Headers("authorization") auth: string, @Param("id") id: string) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.getUser(organizationId, id);
  }

  @Public()
  @Post("Users/:id/update")
  async updateUser(@Headers("authorization") auth: string, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.updateUser(organizationId, id, body);
  }

  @Public()
  @Post("Users/:id/deactivate")
  async deactivateUser(@Headers("authorization") auth: string, @Param("id") id: string) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.deactivateUser(organizationId, id);
  }

  @Public()
  @Post("Groups")
  async upsertGroup(@Headers("authorization") auth: string, @Body() body: Record<string, unknown>) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.upsertGroup(organizationId, body);
  }

  @Public()
  @Get("Groups")
  async listGroups(@Headers("authorization") auth: string) {
    const { organizationId } = await this.scim.authenticate(auth);
    return this.scim.listGroups(organizationId);
  }
}

/** API keys (§104). Plaintext is returned only by create/rotate responses. */
@Controller("api-keys")
export class ApiKeysController {
  constructor(private readonly keys: KeysService) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) { return this.keys.listApiKeys(user); }

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_API_KEYS");
    return this.keys.createPersonalApiKey(user, body);
  }

  @Post(":id/rotate")
  async rotate(@CurrentUser() user: RequestUser, @Param("id") id: string) { return this.keys.rotateApiKey(user, id); }

  @Delete(":id")
  async revoke(@CurrentUser() user: RequestUser, @Param("id") id: string) { return this.keys.revokeApiKey(user, id); }
}

/** Service accounts (§105). */
@Controller("service-accounts")
export class ServiceAccountsController {
  constructor(private readonly keys: KeysService) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    requireIdentityPermission(user, "MANAGE_SERVICE_ACCOUNTS");
    return this.keys.listServiceAccounts(user);
  }

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SERVICE_ACCOUNTS");
    return this.keys.createServiceAccount(user, body);
  }

  @Patch(":id")
  async update(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SERVICE_ACCOUNTS");
    return this.keys.updateServiceAccount(user, id, body);
  }

  @Post(":id/credentials")
  async credential(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    requireIdentityPermission(user, "MANAGE_SERVICE_ACCOUNTS");
    return this.keys.createServiceAccountCredential(user, id, body);
  }

  @Delete(":id")
  async disable(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    requireIdentityPermission(user, "MANAGE_SERVICE_ACCOUNTS");
    return this.keys.updateServiceAccount(user, id, { status: "DISABLED" });
  }
}

