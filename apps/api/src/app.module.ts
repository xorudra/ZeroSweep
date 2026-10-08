import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { PrismaModule } from "./prisma/prisma.module";
import { QueueModule } from "./queue/queue.module";
import { HealthModule } from "./health/health.module";
import { JwtAuthGuard } from "./common/guards/jwt-auth.guard";
import { RolesGuard } from "./common/guards/roles.guard";
import { AuditModule } from "./modules/audit/audit.module";
import { AuthModule } from "./modules/auth/auth.module";
import { UsersModule } from "./modules/users/users.module";
import { OrganizationsModule } from "./modules/organizations/organizations.module";
import { WorkspacesModule } from "./modules/workspaces/workspaces.module";
import { TargetsModule } from "./modules/targets/targets.module";
import { ScopesModule } from "./modules/scopes/scopes.module";
import { AssessmentsModule } from "./modules/assessments/assessments.module";
import { ScansModule } from "./modules/scans/scans.module";
import { FindingsModule } from "./modules/findings/findings.module";
import { ReportsModule } from "./modules/reports/reports.module";
import { ToolsModule } from "./modules/tools/tools.module";
import { IntegrationsModule } from "./modules/integrations/integrations.module";
import { CredentialsModule } from "./modules/credentials/credentials.module";
import { NotificationsModule } from "./modules/notifications/notifications.module";
import { OrchestrationModule } from "./modules/orchestration/orchestration.module";
import { AssetsModule } from "./modules/assets/assets.module";
import { ScannersModule } from "./modules/scanners/scanners.module";
import { ApiSecurityModule } from "./modules/api-security/api-security.module";
import { NetworkModule } from "./modules/network/network.module";
import { VulnerabilitiesModule } from "./modules/vulnerabilities/vulnerabilities.module";
import { RepositoriesModule } from "./modules/repositories/repositories.module";
import { CloudNativeModule } from "./modules/cloud-native/cloud-native.module";
import { CloudSecurityModule } from "./modules/cloud-security/cloud-security.module";
import { ActiveDirectoryModule } from "./modules/active-directory/active-directory.module";
import { SecurityValidationModule } from "./modules/security-validation/security-validation.module";
import { MobileSecurityModule } from "./modules/mobile-security/mobile-security.module";
import { BinarySecurityModule } from "./modules/binary-security/binary-security.module";
import { WirelessSecurityModule } from "./modules/wireless-security/wireless-security.module";
import { VulnerabilityManagementModule } from "./modules/vulnerability-management/vulnerability-management.module";
import { AiSecurityModule } from "./modules/ai-security/ai-security.module";
import { ContinuousSecurityModule } from "./modules/continuous-security/continuous-security.module";
import { IdentityModule } from "./modules/identity/identity.module";

@Module({
  imports: [
    PrismaModule, QueueModule, HealthModule, AuditModule, AuthModule, UsersModule,
    OrganizationsModule, WorkspacesModule, TargetsModule, ScopesModule, AssessmentsModule,
    ScansModule, FindingsModule, ReportsModule, ToolsModule, IntegrationsModule,
    CredentialsModule, NotificationsModule, OrchestrationModule, AssetsModule, ScannersModule,
    ApiSecurityModule, NetworkModule, VulnerabilitiesModule, RepositoriesModule, CloudNativeModule, CloudSecurityModule, ActiveDirectoryModule,
    SecurityValidationModule, MobileSecurityModule, BinarySecurityModule, WirelessSecurityModule, VulnerabilityManagementModule,
    AiSecurityModule,
    ContinuousSecurityModule,
    IdentityModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
