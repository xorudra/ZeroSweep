-- CreateEnum
CREATE TYPE "UserAccountStatus" AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'DEACTIVATED');

-- CreateEnum
CREATE TYPE "OrganizationStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'DEACTIVATED');

-- CreateEnum
CREATE TYPE "MfaMethodType" AS ENUM ('TOTP', 'WEBAUTHN', 'PASSKEY', 'RECOVERY_CODES');

-- CreateEnum
CREATE TYPE "MfaRequirement" AS ENUM ('OPTIONAL', 'REQUIRED_FOR_ADMINS', 'REQUIRED_FOR_ALL');

-- CreateEnum
CREATE TYPE "AuthenticationAssurance" AS ENUM ('AAL1', 'AAL2', 'PHISHING_RESISTANT');

-- CreateEnum
CREATE TYPE "SsoProviderType" AS ENUM ('OIDC', 'SAML');

-- CreateEnum
CREATE TYPE "AuthChallengeType" AS ENUM ('MFA_TOTP', 'WEBAUTHN_REGISTRATION', 'WEBAUTHN_AUTHENTICATION', 'PASSWORD_RESET', 'STEP_UP', 'OIDC_FLOW', 'SAML_FLOW');

-- CreateEnum
CREATE TYPE "AccessReviewStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'COMPLETED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "AccessReviewDecision" AS ENUM ('KEEP', 'REVOKE', 'CHANGE_ROLE', 'DISABLE');

-- CreateEnum
CREATE TYPE "ApiKeyOwnerKind" AS ENUM ('USER', 'SERVICE_ACCOUNT');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "Role" ADD VALUE 'SECURITY_ADMIN';
ALTER TYPE "Role" ADD VALUE 'MEMBER';

-- AlterEnum
ALTER TYPE "MembershipStatus" ADD VALUE 'REVOKED';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'USER_LOGIN_SUCCEEDED';
ALTER TYPE "AuditAction" ADD VALUE 'USER_LOGIN_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'MFA_ENABLED';
ALTER TYPE "AuditAction" ADD VALUE 'MFA_DISABLED';
ALTER TYPE "AuditAction" ADD VALUE 'MFA_CHALLENGE_ISSUED';
ALTER TYPE "AuditAction" ADD VALUE 'PASSKEY_REGISTERED';
ALTER TYPE "AuditAction" ADD VALUE 'PASSKEY_REMOVED';
ALTER TYPE "AuditAction" ADD VALUE 'RECOVERY_CODE_USED';
ALTER TYPE "AuditAction" ADD VALUE 'RECOVERY_CODES_REGENERATED';
ALTER TYPE "AuditAction" ADD VALUE 'SESSION_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'SESSIONS_REVOKED_ALL';
ALTER TYPE "AuditAction" ADD VALUE 'PASSWORD_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'PASSWORD_RESET_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'PASSWORD_RESET_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'SSO_PROVIDER_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SSO_PROVIDER_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SSO_PROVIDER_DISABLED';
ALTER TYPE "AuditAction" ADD VALUE 'SSO_LOGIN_SUCCEEDED';
ALTER TYPE "AuditAction" ADD VALUE 'SSO_LOGIN_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'SCIM_TOKEN_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCIM_TOKEN_ROTATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCIM_USER_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCIM_USER_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCIM_USER_DEACTIVATED';
ALTER TYPE "AuditAction" ADD VALUE 'SCIM_GROUP_UPSERTED';
ALTER TYPE "AuditAction" ADD VALUE 'SERVICE_ACCOUNT_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'SERVICE_ACCOUNT_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'SERVICE_ACCOUNT_DISABLED';
ALTER TYPE "AuditAction" ADD VALUE 'SERVICE_ACCOUNT_CREDENTIAL_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'API_KEY_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'API_KEY_ROTATED';
ALTER TYPE "AuditAction" ADD VALUE 'API_KEY_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'SECURITY_POLICY_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'BREAK_GLASS_LOGIN';
ALTER TYPE "AuditAction" ADD VALUE 'BREAK_GLASS_ENROLLED';
ALTER TYPE "AuditAction" ADD VALUE 'INVITATION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'INVITATION_ACCEPTED';
ALTER TYPE "AuditAction" ADD VALUE 'INVITATION_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'DOMAIN_VERIFICATION_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'DOMAIN_VERIFIED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCESS_REVIEW_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCESS_REVIEW_DECIDED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCESS_REVIEW_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'STEP_UP_REQUIRED';
ALTER TYPE "AuditAction" ADD VALUE 'STEP_UP_SUCCEEDED';
ALTER TYPE "AuditAction" ADD VALUE 'MFA_RESET';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "lastLoginAt" TIMESTAMP(3),
ADD COLUMN     "normalizedEmail" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "status" "UserAccountStatus" NOT NULL DEFAULT 'ACTIVE';

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "dataRegion" TEXT,
ADD COLUMN     "securityContact" TEXT,
ADD COLUMN     "status" "OrganizationStatus" NOT NULL DEFAULT 'ACTIVE';

-- AlterTable
ALTER TABLE "Membership" ADD COLUMN     "invitedBy" TEXT,
ADD COLUMN     "joinedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "WorkspaceMembership" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'VIEWER',
    "status" "MembershipStatus" NOT NULL DEFAULT 'ACTIVE',
    "invitedBy" TEXT,
    "joinedAt" TIMESTAMP(3),
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WorkspaceMembership_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT,
    "tokenHash" TEXT NOT NULL,
    "assurance" "AuthenticationAssurance" NOT NULL DEFAULT 'AAL1',
    "deviceSummary" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "idleExpiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "stepUpAt" TIMESTAMP(3),

    CONSTRAINT "UserSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthChallenge" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "AuthChallengeType" NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "consumedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MfaMethod" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "MfaMethodType" NOT NULL,
    "secretEncrypted" TEXT,
    "credentialId" TEXT,
    "lastUsedStep" BIGINT,
    "isActive" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "MfaMethod_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RecoveryCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RecoveryCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebAuthnCredential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "transports" TEXT,
    "friendlyName" TEXT,
    "isPasskey" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "WebAuthnCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthenticationEvent" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "organizationId" TEXT,
    "eventType" TEXT NOT NULL,
    "ipAddress" TEXT,
    "deviceSummary" TEXT,
    "riskSignals" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthenticationEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnterpriseSsoProvider" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "SsoProviderType" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "enforceSso" BOOLEAN NOT NULL DEFAULT false,
    "jitEnabled" BOOLEAN NOT NULL DEFAULT false,
    "jitDefaultRole" "Role" NOT NULL DEFAULT 'VIEWER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EnterpriseSsoProvider_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OidcProviderConfig" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretRef" TEXT NOT NULL,
    "scopes" TEXT NOT NULL DEFAULT 'openid email profile',
    "emailClaim" TEXT NOT NULL DEFAULT 'email',
    "nameClaim" TEXT NOT NULL DEFAULT 'name',
    "groupsClaim" TEXT NOT NULL DEFAULT 'groups',
    "subjectClaim" TEXT NOT NULL DEFAULT 'sub',

    CONSTRAINT "OidcProviderConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SamlProviderConfig" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "idpEntityId" TEXT NOT NULL,
    "ssoUrl" TEXT NOT NULL,
    "certificate" TEXT NOT NULL,
    "spEntityId" TEXT NOT NULL,
    "emailAttribute" TEXT NOT NULL DEFAULT 'email',
    "nameAttribute" TEXT NOT NULL DEFAULT 'displayName',
    "groupsAttribute" TEXT NOT NULL DEFAULT 'groups',
    "wantEncryptedAssertions" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "SamlProviderConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SamlAssertionConsumption" (
    "id" TEXT NOT NULL,
    "assertionId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SamlAssertionConsumption_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationDomain" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "verificationTokenHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrganizationDomain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationInvitation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "normalizedEmail" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'VIEWER',
    "workspaceIds" JSONB,
    "tokenHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "invitedBy" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "acceptedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrganizationInvitation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimCredential" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "tokenPrefix" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "ScimCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimGroupMapping" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "externalGroup" TEXT NOT NULL,
    "organizationRole" "Role" NOT NULL,
    "workspaceId" TEXT,
    "workspaceRole" "Role",

    CONSTRAINT "ScimGroupMapping_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimExternalRecord" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "externalId" TEXT,
    "localId" TEXT NOT NULL,
    "displayName" TEXT,

    CONSTRAINT "ScimExternalRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServiceAccount" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "workspaceId" TEXT,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "scopes" JSONB NOT NULL,
    "createdBy" TEXT NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ServiceAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiKey" (
    "id" TEXT NOT NULL,
    "ownerKind" "ApiKeyOwnerKind" NOT NULL,
    "ownerId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "scopes" JSONB NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApiKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationSecurityPolicy" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "mfaRequirement" "MfaRequirement" NOT NULL DEFAULT 'OPTIONAL',
    "ssoRequirement" TEXT NOT NULL DEFAULT 'OPTIONAL',
    "passwordLoginAllowed" BOOLEAN NOT NULL DEFAULT true,
    "sessionIdleMinutes" INTEGER NOT NULL DEFAULT 30,
    "sessionAbsoluteMinutes" INTEGER NOT NULL DEFAULT 720,
    "apiKeyMaxLifetimeDays" INTEGER,
    "patAllowed" BOOLEAN NOT NULL DEFAULT true,
    "scimEnabled" BOOLEAN NOT NULL DEFAULT false,
    "jitEnabled" BOOLEAN NOT NULL DEFAULT false,
    "stepUpActions" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrganizationSecurityPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PasswordPolicy" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "minLength" INTEGER NOT NULL DEFAULT 12,
    "maxLength" INTEGER NOT NULL DEFAULT 128,
    "historyCount" INTEGER NOT NULL DEFAULT 5,
    "compromisedCheckEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PasswordPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BreakGlassEnrollment" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BreakGlassEnrollment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccessReview" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "status" "AccessReviewStatus" NOT NULL DEFAULT 'OPEN',
    "createdBy" TEXT NOT NULL,
    "dueAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AccessReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccessReviewItem" (
    "id" TEXT NOT NULL,
    "reviewId" TEXT NOT NULL,
    "subjectType" TEXT NOT NULL,
    "subjectId" TEXT NOT NULL,
    "subjectLabel" TEXT NOT NULL,
    "decision" "AccessReviewDecision",
    "decidedBy" TEXT,
    "decidedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AccessReviewItem_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "WorkspaceMembership_workspaceId_idx" ON "WorkspaceMembership"("workspaceId");

-- CreateIndex
CREATE INDEX "WorkspaceMembership_organizationId_idx" ON "WorkspaceMembership"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "WorkspaceMembership_userId_workspaceId_key" ON "WorkspaceMembership"("userId", "workspaceId");

-- CreateIndex
CREATE UNIQUE INDEX "UserSession_tokenHash_key" ON "UserSession"("tokenHash");

-- CreateIndex
CREATE INDEX "UserSession_userId_idx" ON "UserSession"("userId");

-- CreateIndex
CREATE INDEX "UserSession_organizationId_idx" ON "UserSession"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "AuthChallenge_tokenHash_key" ON "AuthChallenge"("tokenHash");

-- CreateIndex
CREATE INDEX "AuthChallenge_userId_type_idx" ON "AuthChallenge"("userId", "type");

-- CreateIndex
CREATE INDEX "MfaMethod_userId_idx" ON "MfaMethod"("userId");

-- CreateIndex
CREATE INDEX "RecoveryCode_userId_idx" ON "RecoveryCode"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "WebAuthnCredential_credentialId_key" ON "WebAuthnCredential"("credentialId");

-- CreateIndex
CREATE INDEX "WebAuthnCredential_userId_idx" ON "WebAuthnCredential"("userId");

-- CreateIndex
CREATE INDEX "AuthenticationEvent_userId_idx" ON "AuthenticationEvent"("userId");

-- CreateIndex
CREATE INDEX "AuthenticationEvent_organizationId_idx" ON "AuthenticationEvent"("organizationId");

-- CreateIndex
CREATE INDEX "EnterpriseSsoProvider_organizationId_idx" ON "EnterpriseSsoProvider"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "OidcProviderConfig_providerId_key" ON "OidcProviderConfig"("providerId");

-- CreateIndex
CREATE INDEX "OidcProviderConfig_providerId_idx" ON "OidcProviderConfig"("providerId");

-- CreateIndex
CREATE UNIQUE INDEX "SamlProviderConfig_providerId_key" ON "SamlProviderConfig"("providerId");

-- CreateIndex
CREATE INDEX "SamlProviderConfig_providerId_idx" ON "SamlProviderConfig"("providerId");

-- CreateIndex
CREATE UNIQUE INDEX "SamlAssertionConsumption_assertionId_key" ON "SamlAssertionConsumption"("assertionId");

-- CreateIndex
CREATE INDEX "OrganizationDomain_domain_idx" ON "OrganizationDomain"("domain");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationDomain_organizationId_domain_key" ON "OrganizationDomain"("organizationId", "domain");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationInvitation_tokenHash_key" ON "OrganizationInvitation"("tokenHash");

-- CreateIndex
CREATE INDEX "OrganizationInvitation_organizationId_idx" ON "OrganizationInvitation"("organizationId");

-- CreateIndex
CREATE INDEX "OrganizationInvitation_normalizedEmail_idx" ON "OrganizationInvitation"("normalizedEmail");

-- CreateIndex
CREATE UNIQUE INDEX "ScimCredential_organizationId_key" ON "ScimCredential"("organizationId");

-- CreateIndex
CREATE INDEX "ScimGroupMapping_organizationId_idx" ON "ScimGroupMapping"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "ScimGroupMapping_organizationId_externalGroup_key" ON "ScimGroupMapping"("organizationId", "externalGroup");

-- CreateIndex
CREATE INDEX "ScimExternalRecord_organizationId_resourceType_idx" ON "ScimExternalRecord"("organizationId", "resourceType");

-- CreateIndex
CREATE UNIQUE INDEX "ScimExternalRecord_organizationId_resourceType_localId_key" ON "ScimExternalRecord"("organizationId", "resourceType", "localId");

-- CreateIndex
CREATE INDEX "ServiceAccount_organizationId_idx" ON "ServiceAccount"("organizationId");

-- CreateIndex
CREATE INDEX "ApiKey_ownerId_idx" ON "ApiKey"("ownerId");

-- CreateIndex
CREATE INDEX "ApiKey_organizationId_idx" ON "ApiKey"("organizationId");

-- CreateIndex
CREATE INDEX "ApiKey_prefix_idx" ON "ApiKey"("prefix");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationSecurityPolicy_organizationId_key" ON "OrganizationSecurityPolicy"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "PasswordPolicy_organizationId_key" ON "PasswordPolicy"("organizationId");

-- CreateIndex
CREATE INDEX "BreakGlassEnrollment_organizationId_idx" ON "BreakGlassEnrollment"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "BreakGlassEnrollment_organizationId_userId_key" ON "BreakGlassEnrollment"("organizationId", "userId");

-- CreateIndex
CREATE INDEX "AccessReview_organizationId_idx" ON "AccessReview"("organizationId");

-- CreateIndex
CREATE INDEX "AccessReviewItem_reviewId_idx" ON "AccessReviewItem"("reviewId");

-- CreateIndex
CREATE UNIQUE INDEX "User_normalizedEmail_key" ON "User"("normalizedEmail");

-- AddForeignKey
ALTER TABLE "WorkspaceMembership" ADD CONSTRAINT "WorkspaceMembership_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WorkspaceMembership" ADD CONSTRAINT "WorkspaceMembership_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

