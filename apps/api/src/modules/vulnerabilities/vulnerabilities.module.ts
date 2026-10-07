import { Module } from "@nestjs/common";
import { QueueModule } from "../../queue/queue.module";
import { VulnerabilitiesController, CvesController, VulnerabilityIntelligenceController } from "./vulnerabilities.controller";
import { VulnerabilityService } from "./vulnerability.service";
import { IntelligenceService, INTELLIGENCE_FETCHER } from "./intelligence.service";
import { RetestService } from "./retest.service";
import { ScannerImportsService } from "./imports.service";

@Module({
  imports: [QueueModule],
  controllers: [VulnerabilitiesController, CvesController, VulnerabilityIntelligenceController],
  providers: [
    VulnerabilityService, IntelligenceService, RetestService, ScannerImportsService,
    // No egress fetcher is wired in this build: sync attempts honestly
    // record FAILED / stay NEVER_SYNCED (Prompt 11 §30/§87).
    { provide: INTELLIGENCE_FETCHER, useValue: null },
  ],
  exports: [VulnerabilityService, IntelligenceService, RetestService],
})
export class VulnerabilitiesModule {}
