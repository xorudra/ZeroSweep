import { Module } from "@nestjs/common";
import { AiSecurityController } from "./ai-security.controller";
import { AiCopilotService } from "./ai-copilot.service";
import { AiPlatformService } from "./ai-platform.service";
import { AiConfigService } from "./ai-config.service";
import { AiContextService } from "./ai-context.service";
import { AiRouterService } from "./ai-router.service";
import { AiRetrievalService } from "./ai-retrieval.service";
import { AiGatewayService } from "./ai-gateway.service";
import { AiPlannerService } from "./ai-planner.service";
import { AiAgentsService } from "./ai-agents.service";
import { AiV2PlatformService } from "./ai-v2-platform.service";

@Module({
  controllers: [AiSecurityController],
  providers: [
    AiCopilotService, AiPlatformService, AiConfigService, AiContextService,
    // Prompt 36: Copilot V2 services on the same module/architecture.
    AiRouterService, AiRetrievalService, AiGatewayService, AiPlannerService,
    AiAgentsService, AiV2PlatformService,
  ],
  exports: [
    AiCopilotService, AiPlatformService, AiConfigService, AiContextService,
    AiRouterService, AiRetrievalService, AiGatewayService, AiPlannerService,
    AiAgentsService, AiV2PlatformService,
  ],
})
export class AiSecurityModule {}
