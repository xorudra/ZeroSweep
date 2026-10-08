import { Body, Controller, Get, Param, Post } from "@nestjs/common";
import { z } from "zod";
import {
  createMobileDynamicSessionSchema, uploadMobileBuildSchema,
} from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { MobileBinaryV2Service } from "./mobile-binary-v2.service";

const analyzeBodySchema = z.object({
  profile: z.string().min(1).max(64).optional(),
  deviceId: z.string().min(1).optional(),
  trafficAnalysis: z.boolean().default(false),
}).strict();

const dynamicBodySchema = createMobileDynamicSessionSchema.omit({ buildId: true }).extend({
  // Carried ONLY so refusal is explicit + audited (§79/§152) — never
  // executed, never stored.
  scriptBody: z.string().max(20000).optional(),
  shellCommand: z.string().max(2000).optional(),
});

const compareBodySchema = z.object({
  fromBuildId: z.string().min(1),
  toBuildId: z.string().min(1),
}).strict();

const scriptRegistrationSchema = z.object({
  name: z.string().min(1).max(200),
  tool: z.enum(["FRIDA", "OBJECTION"]),
  version: z.string().min(1).max(64),
  purpose: z.string().min(1).max(128).optional(),
  platform: z.enum(["ANDROID", "IOS", "BOTH"]).optional(),
  riskClassification: z.enum(["LOW", "MEDIUM", "HIGH"]).optional(),
  moduleHash: z.string().min(1).max(128),
  scriptBody: z.string().max(20000).optional(),
}).strict();

const trafficBodySchema = z.object({
  proxyTool: z.enum(["MITMPROXY", "BURP_SUITE"]).optional(),
  deviceId: z.string().min(1).optional(),
}).strict();

const redactionPreviewSchema = z.object({
  headers: z.array(z.object({ name: z.string().min(1).max(128), value: z.string().max(4096) })).max(64).optional(),
  body: z.string().max(16384).optional(),
}).strict();

const nlBodySchema = z.object({ text: z.string().min(1).max(2000) }).strict();
const adbBodySchema = z.object({ operation: z.string().min(1).max(256) }).strict();
const objectionBodySchema = z.object({ workflow: z.string().min(1).max(256) }).strict();
const binaryAnalyzeSchema = z.object({ profile: z.string().min(1).max(64).optional() }).strict();

/**
 * Mobile & Binary Security V2 endpoints (Prompt 35 §133). These are
 * the spec's V2 route shapes; every write delegates to the governed
 * Prompt 17/18 services or records a governed V2 record (plan,
 * lineage, coverage, traffic session). There is NO endpoint that
 * installs/runs an app, opens an adb shell, accepts a Frida script
 * body for execution, or returns a raw secret (§164).
 */
@Controller()
export class MobileBinaryV2Controller {
  constructor(private readonly v2: MobileBinaryV2Service) {}

  // Artifacts (§133)
  @Post("mobile/apps/:id/artifacts")
  async uploadArtifact(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(uploadMobileBuildSchema, body ?? {});
    return this.v2.uploadArtifact(user, id, input);
  }

  @Get("mobile/artifacts/:id")
  async getArtifact(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.v2.getArtifact(user, id);
  }

  @Post("mobile/artifacts/:id/analyze")
  async analyzeArtifact(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(analyzeBodySchema, body ?? {});
    return this.v2.analyzeArtifact(user, id, input);
  }

  @Post("mobile/artifacts/:id/dynamic-analysis")
  async dynamicAnalysis(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(dynamicBodySchema, body ?? {});
    return this.v2.requestDynamicAnalysis(user, id, input as never);
  }

  @Get("mobile/dynamic-sessions/:id")
  async getDynamicSession(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.v2.getDynamicSession(user, id);
  }

  // Runtime policy (§75–§84)
  @Post("mobile/adb-operation")
  async adbOperation(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(adbBodySchema, body ?? {});
    return this.v2.evaluateAdb(user, input.operation);
  }

  @Post("mobile/instrumentation-scripts")
  async registerScript(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(scriptRegistrationSchema, body ?? {});
    return this.v2.registerInstrumentationScript(user, input);
  }

  @Post("mobile/objection-workflow")
  async objectionWorkflow(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(objectionBodySchema, body ?? {});
    return this.v2.checkObjectionWorkflow(user, input.workflow);
  }

  // Traffic (§88–§93)
  @Post("mobile/artifacts/:id/traffic-sessions")
  async startTraffic(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(trafficBodySchema, body ?? {});
    return this.v2.startTrafficCapture(user, id, input);
  }

  @Post("mobile/traffic-redaction-preview")
  async redactionPreview(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(redactionPreviewSchema, body ?? {});
    return this.v2.previewTrafficRedaction(user, input);
  }

  // Findings / lineage / coverage (§105–§126/§133)
  @Get("mobile/findings")
  async listFindings(@CurrentUser() user: RequestUser) {
    return this.v2.listMobileFindings(user);
  }

  @Post("mobile/apps/:id/compare")
  async compare(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(compareBodySchema, body ?? {});
    return this.v2.compareVersions(user, id, input);
  }

  @Get("mobile/apps/:id/lineage")
  async lineage(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.v2.listLineage(user, id);
  }

  @Get("mobile/artifacts/:id/coverage")
  async mobileCoverage(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.v2.getMobileCoverage(user, id);
  }

  // Binary (§133)
  @Get("binary/artifacts")
  async listBinary(@CurrentUser() user: RequestUser) {
    return this.v2.listBinaryArtifacts(user);
  }

  @Get("binary/artifacts/:id")
  async getBinary(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.v2.getBinaryArtifact(user, id);
  }

  @Post("binary/artifacts/:id/analyze")
  async analyzeBinary(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(binaryAnalyzeSchema, body ?? {});
    return this.v2.analyzeBinary(user, id, input);
  }

  @Get("binary/artifacts/:id/coverage")
  async binaryCoverage(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.v2.getBinaryCoverage(user, id);
  }

  // Reports & AI (§127–§132)
  @Get("mobile/reports/:kind")
  async reportDefinition(@CurrentUser() user: RequestUser, @Param("kind") kind: string) {
    return this.v2.getReportDefinition(user, kind);
  }

  @Post("mobile/ai/query")
  async nlQuery(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(nlBodySchema, body ?? {});
    return this.v2.nlQuery(user, input.text);
  }
}
