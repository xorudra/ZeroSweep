import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcryptjs";
import { promises as dns } from "node:dns";
import {
  blockedTargetReason, cloudEndpointVerdict,
  generatePkcePair, mapOidcClaims, mapSamlAttributes, normalizeEmail, randomToken, sha256Hex,
  validateDiscovery, validateIdToken, validateSamlResponse, SamlRejected,
} from "@dsrclone/security-sdk";
import { isTenantSecretSlotReference } from "@dsrclone/config";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { SecretResolver } from "../secret-resolver";
import { SessionsService } from "../sessions/sessions.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";

/** Transport to a live IdP. In tests a fixture transport is injected; no
 *  test ever contacts a real identity provider. */
export interface OidcTransport {
  discovery(issuer: string): Promise<Record<string, unknown>>;
  jwks(jwksUri: string): Promise<{ keys: never[] }>;
  token(tokenEndpoint: string, params: Record<string, string>): Promise<{ id_token?: string; error?: string }>;
}

export const OIDC_TRANSPORT = "OIDC_TRANSPORT";

/** SSRF guard for every server-side IdP fetch (same policy as the target
 *  verification fetcher): the endpoint must pass cloudEndpointVerdict
 *  (public https, no embedded credentials, host not in a blocked range)
 *  AND every address it resolves to must clear blockedTargetReason — a
 *  public name resolving into private space is refused too. Redirects
 *  are never followed, so a redirect target is never fetched. */
async function assertPublicIdpEndpoint(rawUrl: string): Promise<void> {
  const verdict = cloudEndpointVerdict(rawUrl);
  if (!verdict.allowed) throw new Error(`IdP endpoint refused: ${verdict.reason ?? "ENDPOINT_BLOCKED"}`);
  const host = new URL(rawUrl).hostname;
  const addresses = await dns.lookup(host, { all: true });
  if (addresses.length === 0 || addresses.some((a) => blockedTargetReason(a.address))) {
    throw new Error("IdP endpoint resolves to a blocked address");
  }
}

export class FetchOidcTransport implements OidcTransport {
  async discovery(issuer: string) {
    const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    await assertPublicIdpEndpoint(url);
    const res = await fetch(url, { redirect: "manual" });
    if (!res.ok) throw new Error(`Discovery failed: ${res.status}`);
    return (await res.json()) as Record<string, unknown>;
  }
  async jwks(jwksUri: string) {
    await assertPublicIdpEndpoint(jwksUri);
    const res = await fetch(jwksUri, { redirect: "manual" });
    if (!res.ok) throw new Error(`JWKS failed: ${res.status}`);
    return (await res.json()) as { keys: never[] };
  }
  async token(tokenEndpoint: string, params: Record<string, string>) {
    await assertPublicIdpEndpoint(tokenEndpoint);
    const res = await fetch(tokenEndpoint, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params).toString() });
    if (res.status >= 300 && res.status < 400) throw new Error("IdP token endpoint redirect refused");
    return (await res.json()) as { id_token?: string; error?: string };
  }
}

/**
 * Enterprise SSO (§48–59, §85–87): OIDC Authorization Code + PKCE and SAML
 * 2.0 with strict validation, per-organization provider configuration with
 * secret REFERENCES only, explicit group→role mapping (unmapped groups can
 * never grant privilege), optional JIT provisioning at a non-privileged
 * default role, and a break-glass path that survives SSO enforcement.
 */
@Injectable()
export class SsoService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly secrets: SecretResolver,
    private readonly sessions: SessionsService,
    private readonly jwt: JwtService,
    @Inject(OIDC_TRANSPORT) private readonly transport: OidcTransport,
  ) {}

  /* --------------------------- provider admin ---------------------------- */
  async listProviders(user: RequestUser) {
    const providers = await this.prisma.enterpriseSsoProvider.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: "asc" } });
    const out = [];
    for (const p of providers) out.push(await this.presentProvider(p));
    return out;
  }

  /** Write-site closure for tenant-supplied secret references: an `env:`
   *  reference may only name an operator-provisioned tenant slot
   *  (env:TENANT_SECRET_*); anything else is rejected at write time, not
   *  merely left unresolvable. Non-env references stay unresolvable. */
  private assertTenantSecretRef(reference: string, field: string) {
    if (reference.startsWith("env:") && !isTenantSecretSlotReference(reference)) {
      throw new BadRequestException(`${field}: env: references must name an operator-provisioned tenant secret slot (env:TENANT_SECRET_*)`);
    }
  }

  async createProvider(user: RequestUser, body: Record<string, unknown>) {
    const type = body.type as string;
    if (type !== "OIDC" && type !== "SAML") throw new BadRequestException("Provider type must be OIDC or SAML");
    if (body.clientSecretRef !== undefined) this.assertTenantSecretRef(String(body.clientSecretRef ?? ""), "clientSecretRef");
    if (type === "OIDC") {
      // The issuer is fetched server-side at login/test time: it must be a
      // public https endpoint before it is persisted (SSRF policy).
      const verdict = cloudEndpointVerdict(String(body.issuer ?? ""));
      if (!verdict.allowed) throw new BadRequestException(`issuer: ${verdict.reason ?? "ENDPOINT_BLOCKED"}`);
    }
    const provider = await this.prisma.enterpriseSsoProvider.create({
      data: {
        organizationId: user.organizationId, name: String(body.name ?? "SSO"), type,
        enabled: false, enforceSso: Boolean(body.enforceSso), jitEnabled: Boolean(body.jitEnabled),
        jitDefaultRole: ((body.jitDefaultRole as string) ?? "VIEWER") as never,
      },
    });
    if (type === "OIDC") {
      await this.prisma.oidcProviderConfig.create({
        data: {
          providerId: provider.id, issuer: String(body.issuer ?? ""), clientId: String(body.clientId ?? ""),
          clientSecretRef: String(body.clientSecretRef ?? ""), scopes: String(body.scopes ?? "openid email profile"),
          emailClaim: String(body.emailClaim ?? "email"), nameClaim: String(body.nameClaim ?? "name"),
          groupsClaim: String(body.groupsClaim ?? "groups"), subjectClaim: String(body.subjectClaim ?? "sub"),
        },
      });
    } else {
      await this.prisma.samlProviderConfig.create({
        data: {
          providerId: provider.id, idpEntityId: String(body.idpEntityId ?? ""), ssoUrl: String(body.ssoUrl ?? ""),
          certificate: String(body.certificate ?? ""), spEntityId: String(body.spEntityId ?? ""),
          acsUrl: String(body.acsUrl ?? ""),
          emailAttribute: String(body.emailAttribute ?? "email"), nameAttribute: String(body.nameAttribute ?? "displayName"),
          groupsAttribute: String(body.groupsAttribute ?? "groups"), wantEncryptedAssertions: Boolean(body.wantEncryptedAssertions),
        },
      });
    }
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "SSO_PROVIDER_CREATED", resourceType: "EnterpriseSsoProvider", resourceId: provider.id as string, metadata: { type } });
    return this.presentProvider(provider);
  }

  async updateProvider(user: RequestUser, providerId: string, body: Record<string, unknown>) {
    await this.ownProvider(user, providerId);
    if (body.clientSecretRef !== undefined) this.assertTenantSecretRef(String(body.clientSecretRef ?? ""), "clientSecretRef");
    const data: Record<string, unknown> = {};
    for (const field of ["enabled", "enforceSso", "jitEnabled", "jitDefaultRole", "name"]) {
      if (body[field] !== undefined) data[field] = body[field];
    }
    if (data.enforceSso === true || data.enabled === true) await this.assertSafeEnforcement(user.organizationId);
    const updated = await this.prisma.enterpriseSsoProvider.update({ where: { id: providerId }, data });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "SSO_PROVIDER_UPDATED", resourceType: "EnterpriseSsoProvider", resourceId: providerId });
    return this.presentProvider(updated);
  }

  /** Configuration test (§89): validates what can be validated without a
   *  user — discovery + issuer for OIDC; metadata + certificate for SAML.
   *  Providers demanding encrypted assertions are honestly NOT_SUPPORTED
   *  by this build's dependency-free SAML stack (§56). */
  async testProvider(user: RequestUser, providerId: string) {
    const provider = await this.ownProvider(user, providerId);
    if (provider.type === "OIDC") {
      const config = await this.prisma.oidcProviderConfig.findUnique({ where: { providerId } });
      if (!config?.issuer || !config?.clientId) return { status: "NOT_CONFIGURED", detail: "Issuer and client ID are required" };
      if (!this.secrets.resolve(config.clientSecretRef as string)) return { status: "NOT_CONFIGURED", detail: "Client secret reference does not resolve" };
      try {
        const doc = await this.transport.discovery(config.issuer as string);
        validateDiscovery(doc, config.issuer as string);
        return { status: "OK", detail: "Discovery document valid; issuer matches configuration" };
      } catch (err) {
        return { status: "INVALID", detail: (err as Error).message };
      }
    }
    const config = await this.prisma.samlProviderConfig.findUnique({ where: { providerId } });
    if (!config?.idpEntityId || !config?.ssoUrl || !config?.certificate) return { status: "NOT_CONFIGURED", detail: "IdP entity ID, SSO URL and certificate are required" };
    if (config.wantEncryptedAssertions) return { status: "NOT_SUPPORTED", detail: "Encrypted assertions require an XML-encryption stack not provisioned in this build" };
    return { status: "OK", detail: "SAML configuration complete; assertions will be signature-validated at the ACS endpoint" };
  }

  /* ------------------------------ OIDC flow ------------------------------ */
  async startOidcLogin(organizationId: string, providerId: string, redirectUri: string) {
    const { provider, config } = await this.oidcConfig(organizationId, providerId);
    if (!provider.enabled) throw new ForbiddenException("SSO provider is not enabled");
    const discovery = validateDiscovery(await this.transport.discovery(config.issuer), config.issuer);
    const state = randomToken(24);
    const nonce = randomToken(24);
    const pkce = generatePkcePair(Buffer.from(randomToken(32)));
    await this.prisma.authChallenge.create({
      data: {
        userId: providerId, type: "OIDC_FLOW", tokenHash: sha256Hex(state),
        expiresAt: new Date(Date.now() + 10 * 60_000),
        metadata: { nonce, codeVerifier: pkce.verifier, organizationId },
      },
    });
    const url = new URL(discovery.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", config.scopes);
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", "S256");
    return { authorizationUrl: url.toString(), state };
  }

  async oidcCallback(organizationId: string, providerId: string, body: { code: string; state: string; redirectUri: string }) {
    const { provider, config } = await this.oidcConfig(organizationId, providerId);
    const challenge = await this.prisma.authChallenge.findUnique({ where: { tokenHash: sha256Hex(body.state) } });
    if (!challenge || challenge.type !== "OIDC_FLOW" || challenge.consumedAt || new Date(challenge.expiresAt as Date).getTime() < Date.now()) {
      await this.failEvent(organizationId, "SSO_LOGIN", "STATE_INVALID");
      throw new UnauthorizedException("SSO login failed");
    }
    await this.prisma.authChallenge.update({ where: { id: challenge.id }, data: { consumedAt: new Date() } });
    const metadata = challenge.metadata as { nonce: string; codeVerifier: string };
    const clientSecret = this.secrets.resolve(config.clientSecretRef);
    if (!clientSecret) throw new BadRequestException("SSO provider is NOT_CONFIGURED: client secret reference does not resolve");
    const discovery = validateDiscovery(await this.transport.discovery(config.issuer), config.issuer);
    const tokenResponse = await this.transport.token(discovery.tokenEndpoint, {
      grant_type: "authorization_code", code: body.code, redirect_uri: body.redirectUri,
      client_id: config.clientId, client_secret: clientSecret, code_verifier: metadata.codeVerifier,
    });
    if (!tokenResponse.id_token) { await this.failEvent(organizationId, "SSO_LOGIN", "TOKEN_EXCHANGE"); throw new UnauthorizedException("SSO login failed"); }
    const jwks = await this.transport.jwks(discovery.jwksUri);
    let claims: Record<string, unknown>;
    try {
      claims = validateIdToken({ idToken: tokenResponse.id_token, jwks, expectedIssuer: config.issuer, expectedAudience: config.clientId, expectedNonce: metadata.nonce, nowMs: Date.now() });
    } catch {
      await this.failEvent(organizationId, "SSO_LOGIN", "ID_TOKEN_INVALID");
      throw new UnauthorizedException("SSO login failed");
    }
    const identity = mapOidcClaims(claims, config);
    return this.completeSsoLogin(provider, identity);
  }

  /* ------------------------------ SAML flow ------------------------------ */
  async startSamlLogin(organizationId: string, providerId: string) {
    const { provider } = await this.samlConfig(organizationId, providerId);
    if (!provider.enabled) throw new ForbiddenException("SSO provider is not enabled");
    const requestId = `_${randomToken(16)}`;
    await this.prisma.authChallenge.create({
      data: { userId: providerId, type: "SAML_FLOW", tokenHash: sha256Hex(requestId), expiresAt: new Date(Date.now() + 10 * 60_000), metadata: { organizationId } },
    });
    return { requestId, ssoUrl: (await this.samlConfig(organizationId, providerId)).config.ssoUrl };
  }

  async samlAcs(organizationId: string, providerId: string, body: { samlResponse: string; relayState?: string }) {
    const { provider, config } = await this.samlConfig(organizationId, providerId);
    if (!provider.enabled) throw new ForbiddenException("SSO provider is not enabled");
    if (config.wantEncryptedAssertions) throw new BadRequestException("Provider demands encrypted assertions — NOT_SUPPORTED in this build");
    // The expected recipient comes ONLY from server configuration — never
    // from the unauthenticated request.
    if (!config.acsUrl) throw new BadRequestException("SAML provider is NOT_CONFIGURED: no ACS URL in provider configuration");
    // Request correlation is MANDATORY for SP-initiated login (as the OIDC
    // callback already requires for state): the relayState must name a
    // live, unconsumed SAML_FLOW challenge bound to this org + provider,
    // and its request id is the required InResponseTo. Unsolicited
    // responses are rejected.
    const challenge = body.relayState
      ? await this.prisma.authChallenge.findUnique({ where: { tokenHash: sha256Hex(body.relayState) } })
      : null;
    if (
      !challenge || challenge.type !== "SAML_FLOW" || challenge.consumedAt
      || new Date(challenge.expiresAt as Date).getTime() < Date.now()
      || (challenge.userId as string) !== providerId
      || (challenge.metadata as { organizationId?: string } | null)?.organizationId !== organizationId
    ) {
      await this.failEvent(organizationId, "SSO_LOGIN", "STATE_INVALID");
      throw new UnauthorizedException("SSO login failed");
    }
    await this.prisma.authChallenge.update({ where: { id: challenge.id }, data: { consumedAt: new Date() } });
    const expectedInResponseTo = body.relayState as string;
    const xml = Buffer.from(body.samlResponse, "base64").toString("utf8");
    let identity;
    try {
      identity = validateSamlResponse({
        responseXml: xml, idpEntityId: config.idpEntityId, idpCertificatePem: config.certificate,
        spEntityId: config.spEntityId, acsUrl: config.acsUrl as string, expectedInResponseTo, nowMs: Date.now(),
      });
    } catch (err) {
      if (err instanceof SamlRejected) await this.failEvent(organizationId, "SSO_LOGIN", "ASSERTION_INVALID");
      throw new UnauthorizedException("SSO login failed");
    }
    // Replay protection (§55): an assertion id may be consumed exactly once.
    const consumed = await this.prisma.samlAssertionConsumption.findUnique({ where: { assertionId: identity.assertionId } });
    if (consumed) { await this.failEvent(organizationId, "SSO_LOGIN", "ASSERTION_REPLAY"); throw new UnauthorizedException("SSO login failed"); }
    await this.prisma.samlAssertionConsumption.create({ data: { assertionId: identity.assertionId, expiresAt: new Date(Date.now() + 10 * 60_000) } });
    const mapped = mapSamlAttributes(identity, config);
    return this.completeSsoLogin(provider, mapped);
  }

  /* ------------------------- shared login completion ---------------------- */
  private async completeSsoLogin(provider: Record<string, unknown>, identity: { email: string; displayName: string; groups: string[] }) {
    const organizationId = provider.organizationId as string;
    const normalized = normalizeEmail(identity.email);
    let user = await this.prisma.user.findUnique({ where: { normalizedEmail: normalized } })
      ?? await this.prisma.user.findUnique({ where: { email: identity.email } });
    let membership = user ? await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId } }) : null;
    const mappedRole = await this.mappedRoleForGroups(organizationId, identity.groups);
    // JIT gates EVERY provisioning side effect of SSO login — a new user
    // row AND a first membership for a pre-existing user alike.
    const orgPolicy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId } });
    const jitAllowed = Boolean(provider.jitEnabled) && Boolean(orgPolicy?.jitEnabled ?? true);
    if (!user) {
      if (!jitAllowed) { await this.failEvent(organizationId, "SSO_LOGIN", "JIT_DISABLED"); throw new UnauthorizedException("SSO login failed"); }
      // JIT (§86/87): account is created at the provider's configured
      // default role. A group mapping may raise it ONLY through the explicit
      // approved mapping table — never from a raw claim.
      const unusablePassword = await bcrypt.hash(randomToken(32), 12);
      user = await this.prisma.user.create({
        data: { email: identity.email, normalizedEmail: normalized, name: identity.displayName, passwordHash: unusablePassword, status: "ACTIVE", lastLoginAt: new Date() },
      });
      membership = await this.prisma.membership.create({
        data: { userId: user.id, organizationId, role: (mappedRole ?? (provider.jitDefaultRole as string) ?? "VIEWER") as never, status: "ACTIVE", joinedAt: new Date() },
      });
    } else {
      if ((user.status as string) === "DEACTIVATED" || (user.status as string) === "SUSPENDED" || !(user.isActive as boolean)) {
        await this.failEvent(organizationId, "SSO_LOGIN", "USER_INACTIVE");
        throw new UnauthorizedException("SSO login failed");
      }
      if (!membership) {
        if (!jitAllowed) { await this.failEvent(organizationId, "SSO_LOGIN", "JIT_DISABLED"); throw new UnauthorizedException("SSO login failed"); }
        membership = await this.prisma.membership.create({
          data: { userId: user.id, organizationId, role: (mappedRole ?? (provider.jitDefaultRole as string) ?? "VIEWER") as never, status: "ACTIVE", joinedAt: new Date() },
        });
      } else if (membership.status !== "ACTIVE") {
        await this.failEvent(organizationId, "SSO_LOGIN", "MEMBERSHIP_INACTIVE");
        throw new UnauthorizedException("SSO login failed");
      } else if (mappedRole) {
        membership = await this.prisma.membership.update({ where: { id: membership.id }, data: { role: mappedRole as never } });
      }
      await this.prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    }
    const session = await this.sessions.createSession({
      id: user.id as string, email: user.email as string, organizationId, role: membership.role as string, assurance: "AAL2",
    });
    await this.prisma.authenticationEvent.create({ data: { userId: user.id, organizationId, eventType: "SSO_LOGIN" } });
    await this.audit.record({ actorId: user.id as string, organizationId, action: "SSO_LOGIN_SUCCEEDED", resourceType: "EnterpriseSsoProvider", resourceId: provider.id as string });
    return {
      user: { id: user.id, email: user.email, name: user.name },
      accessToken: this.jwt.sign({ sub: user.id, email: user.email, organizationId, role: membership.role, sid: session.sessionId }),
      sessionToken: session.sessionToken, sessionId: session.sessionId,
    };
  }

  /** Group → role resolution goes ONLY through the explicit approved
   *  mapping table (§70/71 reused for SSO claims); unmapped groups grant
   *  nothing (§87, §131). Highest mapped privilege wins deterministically. */
  private async mappedRoleForGroups(organizationId: string, groups: string[]): Promise<string | null> {
    if (groups.length === 0) return null;
    const mappings = await this.prisma.scimGroupMapping.findMany({ where: { organizationId } });
    const order = ["VIEWER", "MEMBER", "ANALYST", "SECURITY_ENGINEER", "SECURITY_ADMIN", "ADMIN", "OWNER"];
    let best: string | null = null;
    for (const mapping of mappings) {
      if (groups.includes(mapping.externalGroup as string)) {
        const role = mapping.organizationRole as string;
        if (!best || order.indexOf(role) > order.indexOf(best)) best = role;
      }
    }
    return best;
  }

  /* ------------------------------ break-glass ----------------------------- */
  async enrollBreakGlass(actor: RequestUser, userId: string) {
    const count = await this.prisma.breakGlassEnrollment.count({ where: { organizationId: actor.organizationId, status: "ACTIVE" } });
    if (count >= 3) throw new BadRequestException("Break-glass accounts are limited to 3 per organization (§59)");
    const enrollment = await this.prisma.breakGlassEnrollment.create({ data: { organizationId: actor.organizationId, userId, status: "ACTIVE" } });
    await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "BREAK_GLASS_ENROLLED", resourceType: "BreakGlassEnrollment", resourceId: enrollment.id as string });
    return enrollment;
  }

  /** §100: SSO cannot be enforced into a lockout — enforcement requires a
   *  break-glass enrollment OR a verified domain recovery path. */
  private async assertSafeEnforcement(organizationId: string) {
    const [breakGlass, verifiedDomains] = await Promise.all([
      this.prisma.breakGlassEnrollment.count({ where: { organizationId, status: "ACTIVE" } }),
      this.prisma.organizationDomain.count({ where: { organizationId, status: "VERIFIED" } }),
    ]);
    if (breakGlass === 0 && verifiedDomains === 0) {
      throw new BadRequestException("Refusing to enable/enforce SSO without a validated recovery path: enroll a break-glass administrator or verify a domain first (§100)");
    }
  }

  private async ownProvider(user: RequestUser, providerId: string) {
    const provider = await this.prisma.enterpriseSsoProvider.findFirst({ where: { id: providerId, organizationId: user.organizationId } });
    if (!provider) throw new NotFoundException("SSO provider not found");
    return provider;
  }

  private async oidcConfig(organizationId: string, providerId: string) {
    const provider = await this.prisma.enterpriseSsoProvider.findFirst({ where: { id: providerId, organizationId } });
    if (!provider || provider.type !== "OIDC") throw new NotFoundException("OIDC provider not found");
    const config = await this.prisma.oidcProviderConfig.findUnique({ where: { providerId } });
    if (!config) throw new NotFoundException("OIDC configuration not found");
    return { provider, config };
  }

  private async samlConfig(organizationId: string, providerId: string) {
    const provider = await this.prisma.enterpriseSsoProvider.findFirst({ where: { id: providerId, organizationId } });
    if (!provider || provider.type !== "SAML") throw new NotFoundException("SAML provider not found");
    const config = await this.prisma.samlProviderConfig.findUnique({ where: { providerId } });
    if (!config) throw new NotFoundException("SAML configuration not found");
    return { provider, config };
  }

  private async presentProvider(p: Record<string, unknown>) {
    const base = { id: p.id, name: p.name, type: p.type, enabled: p.enabled, enforceSso: p.enforceSso, jitEnabled: p.jitEnabled, jitDefaultRole: p.jitDefaultRole };
    if (p.type === "OIDC") {
      const config = await this.prisma.oidcProviderConfig.findUnique({ where: { providerId: p.id as string } });
      return { ...base, oidc: config ? { issuer: config.issuer, clientId: config.clientId, clientSecretRef: config.clientSecretRef, clientSecretConfigured: Boolean(this.secrets.resolve(config.clientSecretRef as string)), scopes: config.scopes } : null };
    }
    const config = await this.prisma.samlProviderConfig.findUnique({ where: { providerId: p.id as string } });
    return { ...base, saml: config ? { idpEntityId: config.idpEntityId, ssoUrl: config.ssoUrl, spEntityId: config.spEntityId, acsUrl: config.acsUrl, certificateConfigured: Boolean(config.certificate), wantEncryptedAssertions: config.wantEncryptedAssertions } : null };
  }

  private async failEvent(organizationId: string, eventType: string, reason: string) {
    await this.prisma.authenticationEvent.create({ data: { organizationId, eventType: `${eventType}_FAILED`, riskSignals: { reason } } });
  }
}
