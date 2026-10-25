import { Inject, Injectable } from "@nestjs/common";
import {
  routeAiModel, type AiDataClassification, type AiSecurityTaskType,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireAiPermission } from "./permissions";
import { AiConfigService } from "./ai-config.service";

/**
 * SecurityAiModelRouter — API face (Prompt 36 §5/§6). Resolves the
 * deterministic SDK route decision over the workspace's REAL registry
 * rows + tenant data policy. NOT_CONFIGURED is a first-class honest
 * outcome (§119): in this build only the in-process MOCK transport is
 * provisioned, so external/LOCAL models route as NOT_CONFIGURED and
 * the copilot degrades to RULE_BASED, exactly as in Prompt 21.
 */
@Injectable()
export class AiRouterService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly config: AiConfigService,
  ) {}

  async route(user: RequestUser, workspaceId: string, taskType: AiSecurityTaskType, maxClassification: AiDataClassification = "INTERNAL") {
    requireAiPermission(user, "USE_AI_COPILOT");
    const [models, policy] = await Promise.all([
      this.config.listModelCapabilities(workspaceId),
      this.config.getRoutingPolicy(workspaceId),
    ]);
    const decision = routeAiModel({ taskType, maxClassification, models: models as never, policy });
    return {
      taskType,
      status: decision.status,
      model: decision.model ? {
        modelId: decision.model.modelId, providerName: decision.model.providerName,
        modelName: decision.model.modelName, costClass: decision.model.costClass,
        latencyClass: decision.model.latencyClass, contextWindow: decision.model.contextWindow,
      } : null,
      reasons: decision.reasons,
      rejected: decision.rejected,
    };
  }

  async capabilities(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    return {
      routing: await this.config.getRoutingPolicy(workspaceId),
      models: await this.config.listModelCapabilities(workspaceId),
    };
  }
}
