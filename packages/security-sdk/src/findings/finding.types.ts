import type { Severity } from "@dsrclone/types";

/** Normalized scanner output — every adapter translates into this shape. */
export interface NormalizedFinding {
  title: string;
  description: string;
  severity: Severity;
  confidence: number; // 0..1
  host?: string;
  port?: number;
  protocol?: string;
  endpoint?: string;
  parameter?: string;
  cve?: string; // never invented: unknown stays undefined
  cwe?: string;
  cvssScore?: number;
  cvssVector?: string;
  owaspCategory?: string;
  evidence?: string;
  remediation?: string;
  references: string[];
  sourceTool: string;
  sourceFingerprint: string;
}

export interface NormalizedAsset { host: string; ip?: string; type: string; }
export interface NormalizedService { host: string; port: number; protocol: string; name?: string; }
export interface NormalizedEndpoint { url: string; method?: string; statusCode?: number; }
export interface NormalizedTechnology { name: string; version?: string; host?: string; }

export interface NormalizedSecurityResult {
  assets: NormalizedAsset[];
  services: NormalizedService[];
  endpoints: NormalizedEndpoint[];
  technologies: NormalizedTechnology[];
  findings: NormalizedFinding[];
  artifacts: import("../artifacts/artifact.types").ArtifactMetadata[];
  metrics: Record<string, number>;
  /** True when produced by the Mock adapter — fixture data, NOT real results. */
  mock: boolean;
}
