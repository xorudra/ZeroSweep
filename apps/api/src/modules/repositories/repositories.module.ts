import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { RepositoriesController, SourceScansController } from "./repositories.controller";
import { RepositoriesService } from "./repositories.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [RepositoriesController, SourceScansController],
  providers: [RepositoriesService],
  exports: [RepositoriesService],
})
export class RepositoriesModule {}
