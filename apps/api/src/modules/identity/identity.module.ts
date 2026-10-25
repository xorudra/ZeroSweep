import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { loadEnv } from "@zerosweep/config";
import { AuditModule } from "../audit/audit.module";
import { AuthModule } from "../auth/auth.module";
import { AuthFlowService } from "./auth-flow.service";
import { SecretResolver } from "./secret-resolver";
import { SessionsService } from "./sessions/sessions.service";
import { MfaService } from "./mfa/mfa.service";
import { WebAuthnService } from "./webauthn/webauthn.service";
import { FetchOidcTransport, OIDC_TRANSPORT, SsoService } from "./sso/sso.service";
import { ScimService } from "./scim/scim.service";
import { KeysService } from "./keys/keys.service";
import { GovernanceService } from "./governance/governance.service";
import {
  ApiKeysController, IdentityAuthController, IdentityOrganizationsController,
  InvitationsController, ScimController, ServiceAccountsController, SsoController,
} from "./identity.controller";

/**
 * Prompt 23 — Enterprise Authentication, SSO, MFA, SCIM & Organization
 * Management. Layers ON TOP of the existing local auth (AuthModule is
 * imported, never replaced): sessions, MFA/passkeys, OIDC/SAML SSO with
 * break-glass, SCIM provisioning, service accounts/API keys, and identity
 * governance (policies, domains, invitations, access reviews).
 */
@Module({
  imports: [
    AuditModule,
    AuthModule,
    JwtModule.register({ secret: loadEnv().JWT_SECRET, signOptions: { expiresIn: loadEnv().JWT_EXPIRES_IN } }),
  ],
  controllers: [
    IdentityAuthController, IdentityOrganizationsController, InvitationsController,
    SsoController, ScimController, ApiKeysController, ServiceAccountsController,
  ],
  providers: [
    SecretResolver, SessionsService, MfaService, WebAuthnService, SsoService, ScimService,
    KeysService, GovernanceService, AuthFlowService,
    { provide: OIDC_TRANSPORT, useClass: FetchOidcTransport },
  ],
  exports: [SessionsService, MfaService, SsoService, ScimService, KeysService, GovernanceService],
})
export class IdentityModule {}
