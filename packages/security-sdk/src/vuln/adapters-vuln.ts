import type { AdapterInputField, ToolMetadata } from "../adapter/adapter.types";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { HOSTS_FIELD, TIMEOUT_FIELD, URLS_FIELD, type ReconPlanParts } from "../recon/recon-adapter.base";
import { clampVulnBudget } from "./budget";
import { NiktoParser, NucleiParser, SslyzeParser, TestsslParser, type ParsedVuln, type VulnParser } from "./parsers-vuln";
import {
  GOVERNED_TEMPLATE_DIR, NUCLEI_TEMPLATE_CATALOG, isTemplateAutomatable, selectTemplates,
} from "./template-policy";
import { VulnAdapterBase } from "./vuln-adapter.base";

/**
 * Prompt 7 adapters (§2): Nuclei, Nikto, testssl.sh, SSLyze — the first
 * findings-producing adapters. All run through the existing
 * SecurityToolAdapter contract + ToolRunner (argument arrays only, no
 * shell). Rates/concurrency/timeouts are clamped to the platform vuln
 * budget in code (§8/§51/§52); profiles can lower them, never raise them.
 * Redirects are never followed by these plans (§53): targets come only
 * from verified, in-scope stage inputs (§7/§13).
 */

export const SERVICES_FIELD: AdapterInputField = { name: "services", type: "string[]", description: "Authorized TLS service addresses (host:port) produced by earlier stages — TLS tools run only against these (§13)" };
export const RPS_FIELD: AdapterInputField = { name: "requestsPerSecond", type: "number", min: 1, max: 150, description: "Request rate ceiling, clamped to the platform vuln budget (§52)" };
export const CONCURRENCY_FIELD_V: AdapterInputField = { name: "concurrency", type: "number", min: 1, max: 25, description: "Tool concurrency ceiling, clamped to the platform vuln budget" };
export const APPROVED_TEMPLATES_FIELD: AdapterInputField = { name: "approvedTemplateIds", type: "string[]", description: "Administrator-approved REVIEW_REQUIRED template ids, derived by the worker from the profile — never client-supplied (§4)" };

function meta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "category" | "riskLevel" | "capabilities" | "supportedTargetTypes" | "supportedOutputFormats">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    toolVersion: undefined,
    homepage: undefined,
    licenseType: "OPEN_SOURCE",
    executionMode: "CONTAINER",
    requiresCredentials: [],
    requiresApproval: false,
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 900,
    maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 900 },
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
    ...partial,
  } as ToolMetadata;
}

function startUrl(target: AdapterTarget): string {
  return target.value.includes("://") ? target.value : `https://${target.host}/`;
}

/** TLS service selection (§13): explicit stage-input services win; else
 *  derive host:443 from https URLs; else the target itself on 443. Never
 *  "every port". Capped by the budget's maxTlsServices. */
export function tlsServicesFor(target: AdapterTarget, config: Record<string, unknown>, maxTlsServices: number): string[] {
  const explicit = Array.isArray(config.services) ? (config.services as string[]) : [];
  const derived: string[] = [];
  for (const s of explicit) {
    if (typeof s === "string" && /^[\w.-]+:\d{1,5}$/.test(s)) derived.push(s);
  }
  if (derived.length === 0) {
    const urls = Array.isArray(config.urls) ? (config.urls as string[]) : [];
    for (const u of urls) {
      try {
        const parsed = new URL(u);
        if (parsed.protocol === "https:") derived.push(`${parsed.hostname}:${parsed.port || 443}`);
      } catch { /* unparseable inputs are ignored, never executed */ }
    }
  }
  if (derived.length === 0) derived.push(`${target.host}:443`);
  return [...new Set(derived)].slice(0, Math.max(1, maxTlsServices));
}

// ------------------------------- Nuclei (§3–§8) -------------------------------

export class NucleiAdapter extends VulnAdapterBase {
  readonly executable = "nuclei";
  readonly containerImage = "projectdiscovery/nuclei";
  readonly versionArgs = ["-version"];
  protected readonly parser: VulnParser = new NucleiParser();
  readonly metadata = meta({
    id: "nuclei", slug: "nuclei", name: "Nuclei",
    description: "Template-based vulnerability scanner, restricted to the platform's governed SAFE template policy (Prompt 7 §4).",
    homepage: "https://github.com/projectdiscovery/nuclei",
    category: "WEB", riskLevel: "MODERATE",
    capabilities: ["VULNERABILITY_SCANNING", "MISCONFIGURATION_DETECTION", "EXPOSURE_DETECTION", "TECHNOLOGY_VALIDATION"],
    supportedTargetTypes: ["WEB_APPLICATION", "DOMAIN", "API"],
    supportedOutputFormats: ["JSONL"],
    defaultTimeoutSeconds: 1200, maxTimeoutSeconds: 3600,
    resources: { cpu: "2", memory: "1Gi", timeoutSeconds: 1200 },
    inputSchema: [URLS_FIELD, HOSTS_FIELD, TIMEOUT_FIELD, RPS_FIELD, CONCURRENCY_FIELD_V, APPROVED_TEMPLATES_FIELD],
  });

  /** Template selection for a run (§4): governed catalog only. Exposed so
   *  plans, metrics and admin UI all read the SAME selection. */
  selectionFor(config: Record<string, unknown>) {
    const budget = clampVulnBudget({});
    const approved = Array.isArray(config.approvedTemplateIds) ? (config.approvedTemplateIds as string[]) : [];
    return selectTemplates({ approvedReviewIds: approved, maxTemplates: budget.maxNucleiTemplates });
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampVulnBudget({
      nucleiRequestsPerSecond: typeof config.requestsPerSecond === "number" ? config.requestsPerSecond : undefined,
      nucleiConcurrency: typeof config.concurrency === "number" ? config.concurrency : undefined,
    });
    const selection = this.selectionFor(config);
    const excludedIds = NUCLEI_TEMPLATE_CATALOG
      .filter((t) => !selection.selected.some((s) => s.id === t.id))
      .map((t) => t.id);
    const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [startUrl(target)];
    return {
      args: [
        "-jsonl", "-silent", "-no-color",
        "-rate-limit", String(budget.nucleiRequestsPerSecond),
        "-concurrency", String(budget.nucleiConcurrency),
        "-timeout", "10", "-retries", "1",
        "-no-interactsh", // OAST interaction checks are outside the SAFE policy
        "-t", GOVERNED_TEMPLATE_DIR,
        ...(excludedIds.length > 0 ? ["-exclude-templates", excludedIds.join(",")] : []),
      ],
      stdin: [...new Set(urls)].slice(0, budget.maxVulnerabilityRequests).join("\n"),
    };
  }

  /** Defense in depth (§4): even if raw output somehow contains a finding
   *  from a template outside the automated selection (stale binary, mixed
   *  collection), normalize() drops it and counts the exclusion — an
   *  INTRUSIVE/DISABLED template finding can never enter results. */
  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedVuln;
    const approved = (this.lastConfig?.approvedTemplateIds as string[] | undefined) ?? [];
    let excluded = 0;
    const kept = (p.findings ?? []).filter((f) => {
      if (!f.templateId) return true;
      if (isTemplateAutomatable(f.templateId, approved)) return true;
      excluded++;
      return false;
    });
    const result = await super.normalize({ ...p, findings: kept });
    if (excluded > 0) {
      result.metrics = { ...result.metrics, policyExcludedTemplates: excluded };
      result.findings = kept;
    }
    return result;
  }

  protected lastConfig: Record<string, unknown> | undefined;
  override async buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>) {
    this.lastConfig = config;
    return super.buildExecutionPlan(target, config);
  }
}

// ------------------------------- Nikto (§9/§10) -------------------------------

export class NiktoAdapter extends VulnAdapterBase {
  readonly executable = "nikto";
  readonly containerImage = "dsrclone/nikto"; // platform image built from the official release
  readonly versionArgs = ["-Version"];
  protected readonly parser: VulnParser = new NiktoParser();
  readonly metadata = meta({
    id: "nikto", slug: "nikto", name: "Nikto",
    description: "Web server security assessment: dangerous files, outdated software and server misconfigurations, normalized through parser classification rules (Prompt 7 §10).",
    homepage: "https://github.com/sullo/nikto",
    category: "WEB", riskLevel: "MODERATE",
    capabilities: ["VULNERABILITY_SCANNING", "WEB_SERVER_SECURITY_ASSESSMENT", "MISCONFIGURATION_DETECTION", "EXPOSURE_DETECTION"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 1800, maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 1800 },
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampVulnBudget({});
    const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [startUrl(target)];
    return {
      args: [
        "-host", urls[0]!,
        "-Format", "json", "-output", "-",
        "-nointeractive",
        "-timeout", "10",
        "-maxtime", String(budget.maxNiktoDurationSeconds),
        "-nolookup", // no reverse-DNS side queries outside scope
      ],
    };
  }
}

// ------------------------------- testssl.sh (§11) -------------------------------

export class TestsslAdapter extends VulnAdapterBase {
  readonly executable = "testssl.sh";
  readonly containerImage = "drwetter/testssl.sh";
  readonly versionArgs = ["--version"];
  protected readonly parser: VulnParser = new TestsslParser();
  readonly metadata = meta({
    id: "testssl", slug: "testssl", name: "testssl.sh",
    description: "TLS configuration assessment: protocols, ciphers, certificate and TLS hardening checks (Prompt 7 §11).",
    homepage: "https://github.com/drwetter/testssl.sh",
    category: "WEB", riskLevel: "LOW",
    capabilities: ["TLS_ANALYSIS", "TLS_CONFIGURATION_ASSESSMENT"],
    supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 900, maxTimeoutSeconds: 3600,
    inputSchema: [URLS_FIELD, SERVICES_FIELD, TIMEOUT_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampVulnBudget({});
    const services = tlsServicesFor(target, config, budget.maxTlsServices);
    return { args: ["--jsonfile", "/dev/stdout", "--quiet", "--warnings", "off", ...services] };
  }
}

// ------------------------------- SSLyze (§12) -------------------------------

export class SslyzeAdapter extends VulnAdapterBase {
  readonly executable = "sslyze";
  readonly containerImage = "dsrclone/sslyze"; // platform image built from the official release
  readonly versionArgs = ["--version"];
  protected readonly parser: VulnParser = new SslyzeParser();
  readonly metadata = meta({
    id: "sslyze", slug: "sslyze", name: "SSLyze",
    description: "Independent TLS + certificate analysis used to cross-corroborate testssl.sh (Prompt 7 §12).",
    homepage: "https://github.com/nabla-c0d3/sslyze",
    category: "WEB", riskLevel: "LOW",
    capabilities: ["TLS_ANALYSIS", "CERTIFICATE_ANALYSIS"],
    supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS"],
    supportedOutputFormats: ["JSON"],
    defaultTimeoutSeconds: 900, maxTimeoutSeconds: 3600,
    inputSchema: [URLS_FIELD, SERVICES_FIELD, TIMEOUT_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const budget = clampVulnBudget({});
    const services = tlsServicesFor(target, config, budget.maxTlsServices);
    return {
      args: [
        "--json_out=-",
        "--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
        "--reneg", "--heartbleed", "--robot",
        ...services,
      ],
    };
  }
}
