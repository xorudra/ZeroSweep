import { Injectable } from "@nestjs/common";
import type { EasmSourceKind } from "@dsrclone/security-sdk";

/**
 * Discovery transport seam (Prompt 29 §12/§36/§130). A transport
 * executes governed adapters (Amass passive, Subfinder, CT providers,
 * dnsx…) and returns RECORDED results. In this environment no live
 * Internet transports are wired, so the default transport reports
 * NOT_CONFIGURED for every source — honestly, never fabricated: a run
 * with no transport and no submitted recorded results completes with
 * zero candidates and explicit per-source NOT_CONFIGURED results.
 * Tests inject fixture transports through this seam.
 */
export interface EasmTransportResult {
  source: EasmSourceKind;
  status: "OK" | "ERROR" | "NOT_CONFIGURED" | "SKIPPED_POLICY";
  version?: string;
  durationMs: number;
  errorClass?: string;
  payload?: unknown; // shape of one discoverySourceResult entry (DTO)
}

export interface EasmDiscoveryTransport {
  collect(input: {
    programId: string;
    workspaceId: string;
    rootAssets: Array<{ id: string; type: string; value: string; activeTestingStatus: string }>;
    sources: EasmSourceKind[];
  }): Promise<EasmTransportResult[]>;
}

@Injectable()
export class UnconfiguredEasmTransport implements EasmDiscoveryTransport {
  async collect(input: { sources: EasmSourceKind[] }): Promise<EasmTransportResult[]> {
    return input.sources.map((source) => ({
      source,
      status: "NOT_CONFIGURED" as const,
      durationMs: 0,
      errorClass: "TRANSPORT_NOT_CONFIGURED",
    }));
  }
}

/** DI token for the transport seam. */
export const EASM_TRANSPORT = Symbol("EASM_TRANSPORT");
