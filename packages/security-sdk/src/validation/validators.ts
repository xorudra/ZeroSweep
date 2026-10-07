import { BudgetExceededError, ValidationBudgetTracker } from "./budget";
import { getValidator, type ValidatorDescriptor } from "./catalog";
import {
  FIXTURE_CONFIGURATIONS,
  FIXTURE_HTTP,
  FIXTURE_SCANNER_RECHECKS,
  FIXTURE_SERVICES,
  FIXTURE_TLS,
} from "./fixtures";
import type {
  ValidationEvidenceType,
  ValidationFindingView,
  ValidationOutcome,
  ValidationRiskClass,
} from "./types";

/**
 * Validator SDK (Prompt 16 §14) and the safe validators (§15, §25–§29,
 * §69–§76). A SecurityValidator only ever REPEATS a safe observation and
 * compares it with the original finding. Validators receive a transport
 * — the seam between this SDK and the outside world; in production the
 * worker supplies governed adapter-backed transports on isolated
 * validation workers (§45/§46), in tests the fixture transport returns
 * recorded observations. There is deliberately NO transport method that
 * can submit a body, run a command, or mutate anything.
 */

export interface HttpObservation {
  status: number;
  headers: Record<string, string>;
  bodyBytes: number;
  redirects: number;
}

export interface TlsObservation {
  protocols: string[];
  weakCiphers: string[];
  certificateValid: boolean;
  issues: string[];
}

export interface ServiceObservation {
  open: boolean;
  product?: string;
  version?: string;
  banner?: string;
}

export interface ConfigurationObservation {
  issuePresent: boolean;
  detail: Record<string, unknown>;
}

export interface ScannerRecheckObservation {
  reproduced: boolean;
  evidenceSummary: string;
}

export interface ValidationTransport {
  /** Safe GET only — the transport has no write methods at all. */
  httpGet(url: string): Promise<HttpObservation>;
  tlsInspect(host: string, port: number): Promise<TlsObservation>;
  serviceProbe(host: string, port: number): Promise<ServiceObservation>;
  /** Recorded posture/configuration data for cloud, Kubernetes, source,
   *  container and AD rechecks (§26–§29) — read-only by construction. */
  configurationCheck(kind: string, ref: string): Promise<ConfigurationObservation>;
  /** Governed scanner detection recheck (§69): repeats an approved
   *  detection template; never extracts data. */
  scannerRecheck(toolSlug: string, checkRef: string): Promise<ScannerRecheckObservation>;
}

export interface ValidationContext {
  finding: ValidationFindingView;
  parameters: Record<string, string | number | boolean>;
  transport: ValidationTransport;
  budget: ValidationBudgetTracker;
}

export interface EvidenceDraft {
  type: ValidationEvidenceType;
  summary: string;
  content?: Record<string, unknown>;
  sourceTool?: string;
}

export interface ValidatorResult {
  outcome: ValidationOutcome;
  detail: string;
  evidence: EvidenceDraft[];
}

/** §14 interface: supportsFinding / classifyRisk / validatePolicy /
 *  prepare / execute / parseEvidence / cleanup. */
export interface SecurityValidator {
  readonly descriptor: ValidatorDescriptor;
  supportsFinding(finding: ValidationFindingView): boolean;
  classifyRisk(finding: ValidationFindingView): ValidationRiskClass;
  prepare(ctx: ValidationContext): Promise<void>;
  execute(ctx: ValidationContext): Promise<ValidatorResult>;
  parseEvidence(result: ValidatorResult): EvidenceDraft[];
  cleanup(ctx: ValidationContext): Promise<void>;
}

abstract class BaseValidator implements SecurityValidator {
  readonly descriptor: ValidatorDescriptor;

  constructor(slug: string) {
    const descriptor = getValidator(slug);
    if (!descriptor) throw new Error(`validator ${slug} is not in the governed catalog`);
    this.descriptor = descriptor;
  }

  supportsFinding(finding: ValidationFindingView): boolean {
    return this.descriptor.supportsFinding(finding);
  }

  classifyRisk(_finding: ValidationFindingView): ValidationRiskClass {
    return this.descriptor.riskClass;
  }

  async prepare(_ctx: ValidationContext): Promise<void> {}
  async cleanup(_ctx: ValidationContext): Promise<void> {}

  parseEvidence(result: ValidatorResult): EvidenceDraft[] {
    return result.evidence;
  }

  abstract execute(ctx: ValidationContext): Promise<ValidatorResult>;
}

function findingUrl(finding: ValidationFindingView): string {
  if (finding.endpoint) return finding.endpoint;
  const scheme = (finding.port === 443 || finding.port === 8443) ? "https" : "http";
  return `${scheme}://${finding.host}${finding.port ? `:${finding.port}` : ""}/`;
}

const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
];

/** §15: repeat the HTTP request, verify the security header. */
export class HeaderValidator extends BaseValidator {
  constructor() { super("header-recheck"); }

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const url = findingUrl(ctx.finding);
    ctx.budget.consumeTarget(ctx.finding.host ?? url);
    const res = await ctx.transport.httpGet(url);
    const explicit = typeof ctx.parameters.headerName === "string" ? ctx.parameters.headerName.toLowerCase() : undefined;
    const lowerTitle = ctx.finding.title.toLowerCase();
    const inferred = SECURITY_HEADERS.find((h) => lowerTitle.includes(h));
    const header = explicit ?? inferred ?? "content-security-policy";
    const present = Object.keys(res.headers).some((k) => k.toLowerCase() === header);
    return {
      outcome: present ? "FIXED" : "REPRODUCED",
      detail: present
        ? `header ${header} is now present — the original observation no longer reproduces`
        : `header ${header} is still absent (HTTP ${res.status}) — original observation reproduced`,
      evidence: [
        { type: "HTTP_REQUEST", summary: `GET ${url}`, content: { method: "GET", url }, sourceTool: this.descriptor.toolSlug },
        {
          type: "HTTP_RESPONSE",
          summary: `HTTP ${res.status}; ${header} ${present ? "present" : "absent"}`,
          content: { status: res.status, headers: res.headers, headerChecked: header, headerPresent: present },
          sourceTool: this.descriptor.toolSlug,
        },
      ],
    };
  }
}

/** §15/§70: confirm TLS configuration via the governed TLS assessment. */
export class TlsValidator extends BaseValidator {
  constructor() { super("tls-recheck"); }

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const host = ctx.finding.host ?? "";
    const port = ctx.finding.port ?? 443;
    ctx.budget.consumeTarget(host);
    const tls = await ctx.transport.tlsInspect(host, port);
    const weakProtocols = tls.protocols.filter((p) => ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"].includes(p));
    const reproduced = weakProtocols.length > 0 || tls.weakCiphers.length > 0 || !tls.certificateValid;
    return {
      outcome: reproduced ? "REPRODUCED" : "FIXED",
      detail: reproduced
        ? `weak TLS configuration still present: protocols=${tls.protocols.join(",")}${tls.weakCiphers.length ? ` weakCiphers=${tls.weakCiphers.join(",")}` : ""}`
        : `TLS configuration no longer exhibits the finding (protocols=${tls.protocols.join(",")})`,
      evidence: [{
        type: "TLS_RESULT",
        summary: `TLS recheck for ${host}:${port}: ${tls.issues.join("; ") || "no issues"}`,
        content: { host, port, protocols: tls.protocols, weakCiphers: tls.weakCiphers, certificateValid: tls.certificateValid, issues: tls.issues },
        sourceTool: this.descriptor.toolSlug,
      }],
    };
  }
}

/** §15: confirm an exposed endpoint is still reachable unauthenticated. */
export class EndpointExposureValidator extends BaseValidator {
  constructor() { super("endpoint-exposure-recheck"); }

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const url = findingUrl(ctx.finding);
    ctx.budget.consumeTarget(ctx.finding.host ?? url);
    const res = await ctx.transport.httpGet(url);
    const reachable = res.status !== 404 && res.status < 500;
    return {
      outcome: reachable ? "REPRODUCED" : "NOT_REPRODUCED",
      detail: reachable
        ? `endpoint still reachable without authentication (HTTP ${res.status})`
        : `endpoint no longer reachable (HTTP ${res.status}) — not reproduced`,
      evidence: [
        { type: "HTTP_REQUEST", summary: `GET ${url}`, content: { method: "GET", url }, sourceTool: this.descriptor.toolSlug },
        { type: "HTTP_RESPONSE", summary: `HTTP ${res.status}`, content: { status: res.status, headers: res.headers }, sourceTool: this.descriptor.toolSlug },
      ],
    };
  }
}

/** §69 (+§16/§17): repeat the approved Nuclei detection template. For
 *  SQLi/XSS findings this scanner-evidence recheck is the ONLY automated
 *  validation — no extraction, no script execution in real sessions. */
export class NucleiRecheckValidator extends BaseValidator {
  constructor() { super("nuclei-recheck"); }

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const templateId = typeof ctx.parameters.templateId === "string" ? ctx.parameters.templateId : undefined;
    ctx.budget.consumeTarget(ctx.finding.host ?? "");
    const recheck = await ctx.transport.scannerRecheck("nuclei", templateId ?? ctx.finding.fingerprint ?? ctx.finding.id);
    return {
      outcome: recheck.reproduced ? "REPRODUCED" : "NOT_REPRODUCED",
      detail: recheck.reproduced
        ? "governed detection template reproduced the original observation"
        : "governed detection template no longer matches — not reproduced (not a false-positive determination, §38)",
      evidence: [{
        type: "SCANNER_RESULT",
        summary: recheck.evidenceSummary,
        content: { tool: "nuclei", templateId: templateId ?? null, reproduced: recheck.reproduced },
        sourceTool: "nuclei",
      }],
    };
  }
}

/** §25/§72: port still open, service identity, banner/version. */
export class ServicePresenceValidator extends BaseValidator {
  constructor() { super("service-presence-recheck"); }

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const host = ctx.finding.host ?? "";
    const port = ctx.finding.port ?? 0;
    ctx.budget.consumeTarget(host);
    const svc = await ctx.transport.serviceProbe(host, port);
    return {
      outcome: svc.open ? "REPRODUCED" : "NOT_REPRODUCED",
      detail: svc.open
        ? `service still present on ${host}:${port}${svc.product ? ` (${svc.product}${svc.version ? ` ${svc.version}` : ""})` : ""}`
        : `no service answering on ${host}:${port} — not reproduced`,
      evidence: [{
        type: "SERVICE_RESULT",
        summary: `${host}:${port} ${svc.open ? "open" : "closed/filtered"}${svc.product ? ` — ${svc.product}` : ""}`,
        content: { host, port, open: svc.open, product: svc.product ?? null, version: svc.version ?? null, banner: svc.banner ?? null },
        sourceTool: this.descriptor.toolSlug,
      }],
    };
  }
}

/** §24: safe replay of a read-only API request + authorization behavior. */
export class ApiSafeRecheckValidator extends BaseValidator {
  constructor() { super("api-safe-recheck"); }

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const url = findingUrl(ctx.finding);
    ctx.budget.consumeTarget(ctx.finding.host ?? url);
    const res = await ctx.transport.httpGet(url);
    const reproduced = res.status >= 200 && res.status < 300;
    return {
      outcome: reproduced ? "REPRODUCED" : "NOT_REPRODUCED",
      detail: reproduced
        ? `API endpoint still answers an unauthenticated safe replay (HTTP ${res.status})`
        : `API endpoint now challenges or refuses the unauthenticated replay (HTTP ${res.status})`,
      evidence: [
        { type: "HTTP_REQUEST", summary: `GET ${url} (safe replay, read-only)`, content: { method: "GET", url }, sourceTool: this.descriptor.toolSlug },
        { type: "HTTP_RESPONSE", summary: `HTTP ${res.status}`, content: { status: res.status, headers: res.headers }, sourceTool: this.descriptor.toolSlug },
      ],
    };
  }
}

abstract class ConfigurationRecheckValidator extends BaseValidator {
  protected abstract readonly kind: string;

  async execute(ctx: ValidationContext): Promise<ValidatorResult> {
    const ref = this.refFor(ctx.finding);
    const obs = await ctx.transport.configurationCheck(this.kind, ref);
    return {
      outcome: obs.issuePresent ? "REPRODUCED" : "FIXED",
      detail: obs.issuePresent
        ? `${this.kind} configuration issue still present for ${ref} (read-only confirmation)`
        : `${this.kind} configuration issue no longer present for ${ref}`,
      evidence: [{
        type: "CONFIGURATION_RESULT",
        summary: `${this.kind} posture recheck for ${ref}: issue ${obs.issuePresent ? "present" : "absent"}`,
        content: { kind: this.kind, ref, issuePresent: obs.issuePresent, detail: obs.detail },
        sourceTool: this.descriptor.toolSlug,
      }],
    };
  }

  protected abstract refFor(finding: ValidationFindingView): string;
}

/** §26/§73: cloud validation remains READ_ONLY — confirm configuration. */
export class CloudConfigValidator extends ConfigurationRecheckValidator {
  protected readonly kind = "cloud";
  constructor() { super("cloud-config-recheck"); }
  protected refFor(f: ValidationFindingView): string { return f.cloudResourceId ?? ""; }
}

/** §28/§75: confirm K8s posture — no privilege-escalation attempts. */
export class KubernetesPostureValidator extends ConfigurationRecheckValidator {
  protected readonly kind = "kubernetes";
  constructor() { super("kubernetes-posture-recheck"); }
  protected refFor(f: ValidationFindingView): string { return f.clusterRef ?? ""; }
}

/** §74: deterministic SAST/dependency recheck over the same snapshot. */
export class SourceRecheckValidator extends ConfigurationRecheckValidator {
  protected readonly kind = "source";
  constructor() { super("source-recheck"); }
  protected refFor(f: ValidationFindingView): string { return f.ruleId ?? f.componentPurl ?? ""; }
}

/** §27/§75: confirm image digest + CVE presence by static re-analysis. */
export class ContainerImageValidator extends ConfigurationRecheckValidator {
  protected readonly kind = "container";
  constructor() { super("container-image-recheck"); }
  protected refFor(f: ValidationFindingView): string { return f.imageDigest ?? ""; }
}

/** §29/§76: defensive AD posture confirmation — group membership, ACL
 *  relationships, trusts, delegation, certificate templates. The
 *  prohibited AD techniques (§29 list) have no validator at all. */
export class AdPostureValidator extends ConfigurationRecheckValidator {
  protected readonly kind = "activedirectory";
  constructor() { super("ad-posture-recheck"); }
  protected refFor(f: ValidationFindingView): string { return f.directoryObjectId ?? f.directoryDomainId ?? ""; }
}

export const VALIDATOR_IMPLEMENTATIONS: SecurityValidator[] = [
  new HeaderValidator(),
  new TlsValidator(),
  new EndpointExposureValidator(),
  new NucleiRecheckValidator(),
  new ServicePresenceValidator(),
  new ApiSafeRecheckValidator(),
  new CloudConfigValidator(),
  new KubernetesPostureValidator(),
  new SourceRecheckValidator(),
  new ContainerImageValidator(),
  new AdPostureValidator(),
];

export function getValidatorImplementation(slug: string): SecurityValidator | undefined {
  return VALIDATOR_IMPLEMENTATIONS.find((v) => v.descriptor.slug === slug);
}

/**
 * Budget-enforcing transport wrapper (§88): every call consumes budget
 * BEFORE it happens (requests/endpoints), accounts bytes/redirects
 * after, and the dead-man duration check runs on every call (§44). A
 * budget breach throws BudgetExceededError, which the runner turns
 * into a safely-terminated session — never a partial "pass".
 */
export function budgetedTransport(inner: ValidationTransport, budget: ValidationBudgetTracker): ValidationTransport {
  return {
    async httpGet(url: string) {
      budget.consumeRequest(url);
      const res = await inner.httpGet(url);
      budget.consumeBytes(res.bodyBytes);
      for (let i = 0; i < res.redirects; i++) budget.consumeRedirect();
      budget.checkDuration();
      return res;
    },
    async tlsInspect(host: string, port: number) {
      budget.consumeRequest(`${host}:${port}`);
      const res = await inner.tlsInspect(host, port);
      budget.checkDuration();
      return res;
    },
    async serviceProbe(host: string, port: number) {
      budget.consumeRequest(`${host}:${port}`);
      const res = await inner.serviceProbe(host, port);
      budget.checkDuration();
      return res;
    },
    async configurationCheck(kind: string, ref: string) {
      budget.consumeRequest(`${kind}:${ref}`);
      const res = await inner.configurationCheck(kind, ref);
      budget.checkDuration();
      return res;
    },
    async scannerRecheck(toolSlug: string, checkRef: string) {
      budget.consumeRequest(`${toolSlug}:${checkRef}`);
      const res = await inner.scannerRecheck(toolSlug, checkRef);
      budget.checkDuration();
      return res;
    },
  };
}

export { BudgetExceededError };

/** Fixture transport (§83): returns the recorded lab observations.
 *  Unknown destinations answer honestly (404 / closed / absent) — a
 *  fixture never invents a reproduction. */
export class FixtureValidationTransport implements ValidationTransport {
  constructor(private readonly delayMs = 0) {}

  private async pause(): Promise<void> {
    if (this.delayMs > 0) await new Promise((r) => setTimeout(r, this.delayMs));
  }

  async httpGet(url: string): Promise<HttpObservation> {
    await this.pause();
    return FIXTURE_HTTP[url] ?? { status: 404, headers: {}, bodyBytes: 0, redirects: 0 };
  }

  async tlsInspect(host: string, port: number): Promise<TlsObservation> {
    await this.pause();
    return FIXTURE_TLS[`${host}:${port}`] ?? { protocols: ["TLSv1.2", "TLSv1.3"], weakCiphers: [], certificateValid: true, issues: [] };
  }

  async serviceProbe(host: string, port: number): Promise<ServiceObservation> {
    await this.pause();
    return FIXTURE_SERVICES[`${host}:${port}`] ?? { open: false };
  }

  async configurationCheck(kind: string, ref: string): Promise<ConfigurationObservation> {
    await this.pause();
    return FIXTURE_CONFIGURATIONS[`${kind}:${ref}`] ?? { issuePresent: false, detail: {} };
  }

  async scannerRecheck(toolSlug: string, checkRef: string): Promise<ScannerRecheckObservation> {
    await this.pause();
    return FIXTURE_SCANNER_RECHECKS[`${toolSlug}:${checkRef}`] ?? { reproduced: false, evidenceSummary: `no recorded recheck result for ${toolSlug}:${checkRef}` };
  }
}
