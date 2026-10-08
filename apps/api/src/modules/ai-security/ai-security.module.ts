import { Module } from "@nestjs/common";
import { AiSecurityController } from "./ai-security.controller";
import { AiCopilotService } from "./ai-copilot.service";
import { AiPlatformService } from "./ai-platform.service";
import { AiConfigService } from "./ai-config.service";
import { AiContextService } from "./ai-context.service";

@Module({
  controllers: [AiSecurityController],
  providers: [AiCopilotService, AiPlatformService, AiConfigService, AiContextService],
  exports: [AiCopilotService, AiPlatformService, AiConfigService, AiContextService],
})
export class AiSecurityModule {}
