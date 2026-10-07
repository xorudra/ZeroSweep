import type {
  NormalizedApiService, NormalizedEndpoint, NormalizedEndpointParameter, NormalizedFinding, NormalizedGraphqlService,
  NormalizedJwtProfile, NormalizedSecurityResult, NormalizedService,
} from "../findings/finding.types";

/** A finding draft as the API parsers produce it: the common finding
 *  schema plus the curated vulnerability class the Phase 7 correlation
 *  pipeline keys on (§19). All other enrichment (taxonomy CWE/OWASP,
 *  risk scoring) happens downstream — parsers never invent it. */
export interface ApiFindingDraft extends NormalizedFinding {
  vulnClass: string;
  evidenceDetail?: import("../vuln/types").FindingEvidenceDetail;
  referencesDetailed?: import("../vuln/types").NormalizedReference[];
}
import { ReconAdapterBase } from "../recon/recon-adapter.base";
import { emptyParsed, type ParsedRecon, type ReconParser } from "../recon/parsers-common";

/**
 * The API parser result (Prompt 9): recon-shape inventory PLUS API
 * inventory (services, GraphQL, JWT profiles) and — for the schema
 * testing adapter only — findings. Unlike recon parsers, API parsers
 * MAY produce findings, but only from actual tool evidence (§62):
 * imports and route discovery produce inventory, never findings.
 */
export interface ParsedApi {
  findings: ApiFindingDraft[];
  assets: [];
  services: NormalizedService[];
  endpoints: NormalizedEndpoint[];
  parameters: NormalizedEndpointParameter[];
  apiServices: NormalizedApiService[];
  graphqlServices: NormalizedGraphqlService[];
  jwtProfiles: NormalizedJwtProfile[];
  warnings: string[];
  metrics?: Record<string, number>;
}

export function toParsedRecon(p: ParsedApi): ParsedRecon {
  return {
    ...emptyParsed(),
    services: p.services,
    endpoints: p.endpoints,
    ...(p.parameters.length > 0 ? { parameters: p.parameters } : {}),
    records: p.endpoints.length + p.findings.length + p.apiServices.length + p.graphqlServices.length,
    warnings: p.warnings,
    metrics: p.metrics ?? {},
  };
}

/**
 * Base for the Prompt 9 API adapters. Same lifecycle and ToolRunner
 * boundary as every other adapter family (§2). API parsers need
 * execution context (the base URL / schema location chosen in planFor),
 * so subclasses implement `parseApiOutput` and this base wires the
 * ReconParser contract, parse() and normalize() around it.
 */
export abstract class ApiAdapterBase extends ReconAdapterBase {
  protected override readonly parser: ReconParser = {
    tool: "api-adapter",
    parse: (text: string): ParsedRecon => toParsedRecon(this.parseApiOutput(text)),
  };

  /** Parse raw tool output into the API result shape. Implementations
   *  must never throw on malformed output — warnings instead. */
  protected abstract parseApiOutput(text: string): ParsedApi;

  override async parse(raw: string): Promise<unknown> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    const parsed = this.parseApiOutput(text);
    this.lastWarnings = parsed.warnings;
    return parsed;
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedApi;
    return {
      assets: [],
      services: p.services ?? [],
      endpoints: p.endpoints ?? [],
      parameters: p.parameters ?? [],
      technologies: [],
      findings: p.findings ?? [],
      artifacts: [],
      apiServices: p.apiServices ?? [],
      graphqlServices: p.graphqlServices ?? [],
      jwtProfiles: p.jwtProfiles ?? [],
      metrics: {
        ...(p.metrics ?? {}),
        parserWarnings: (p.warnings ?? []).length,
        ...(this.lastOutcome ? { outcomePartial: this.lastOutcome === "PARTIAL" ? 1 : 0 } : {}),
      },
      mock: false,
    };
  }
}
