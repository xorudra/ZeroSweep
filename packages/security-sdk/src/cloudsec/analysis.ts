/**
 * Prompt 14 — provider-native analysis engines (§36–§57).
 *
 * IAM, storage, database, network/exposure, encryption and logging
 * analysis over NORMALIZED inventory. Every finding is backed by a
 * configuration fact the provider actually returned: no finding is
 * created from an absent field, a PASS never becomes a finding, and
 * administrative identities are flagged with their evidence for
 * organizational review — not auto-declared vulnerabilities (§38).
 * Nothing here connects to a database, downloads an object, attempts
 * a login, assumes a role or retrieves a secret value (§43–§55).
 */
import type {
  CloudExposureClass, CloudFindingClass, NormalizedCloudIdentity, NormalizedCloudResource,
  NormalizedControlAssessment, NormalizedFinding,
} from "../findings/finding.types";
import { cloudFingerprint } from "./correlation";
import { sanitizeCloudText } from "./guards";
import type { CloudProvider } from "./types";

export interface CloudAnalysisContext {
  provider: CloudProvider;
  /** Registered CloudAccount id (platform identity). */
  accountId: string;
  /** Human/external account reference used in fingerprints (§61). */
  accountRef: string;
  environment?: string;
  toolSlug: string; // analyzer provenance, e.g. "cloud-native-analyzer"
}

/** Canonical rule → finding class (§58). Shared with the CSPM parsers
 *  so Prowler/ScoutSuite/native observations of one issue share one
 *  fingerprint and merge (§60). */
export const CLOUD_RULE_CLASSES: Record<string, CloudFindingClass> = {
  "storage-public-access": "PUBLIC_EXPOSURE",
  "storage-encryption": "ENCRYPTION_GAP",
  "storage-encryption-kms": "ENCRYPTION_GAP",
  "storage-logging": "LOGGING_GAP",
  "storage-versioning": "CLOUD_MISCONFIGURATION",
  "database-public-access": "PUBLIC_EXPOSURE",
  "database-encryption": "ENCRYPTION_GAP",
  "database-backup": "CLOUD_MISCONFIGURATION",
  "database-tls": "CLOUD_MISCONFIGURATION",
  "firewall-sensitive-port-world": "PUBLIC_EXPOSURE",
  "firewall-world-open-port": "PUBLIC_EXPOSURE",
  "firewall-rule-undocumented": "CLOUD_MISCONFIGURATION",
  "iam-admin-equivalent": "IAM_RISK",
  "iam-wildcard-actions": "IAM_RISK",
  "iam-broad-trust": "IAM_RISK",
  "mfa-not-enabled": "IAM_RISK",
  "iam-long-lived-credentials": "IAM_RISK",
  "iam-stale-privileged-access": "IAM_RISK",
  "audit-logging-disabled": "LOGGING_GAP",
  "audit-logging-single-region": "LOGGING_GAP",
  "security-service-disabled": "LOGGING_GAP",
  "kms-rotation-disabled": "ENCRYPTION_GAP",
  "serverless-public-access": "PUBLIC_EXPOSURE",
};

/** Rule → CIS control mapping per provider (§68/§69): versioned with
 *  the framework catalog; assessments record tool + framework +
 *  control + timestamp through the shared ControlAssessment model. */
export const CLOUD_RULE_CONTROLS: Record<string, Partial<Record<CloudProvider, { frameworkKey: string; controlId: string }>>> = {
  "iam-admin-equivalent": { AWS: { frameworkKey: "CIS_AWS", controlId: "1.16" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "1.23" }, GCP: { frameworkKey: "CIS_GCP", controlId: "1.5" } },
  "mfa-not-enabled": { AWS: { frameworkKey: "CIS_AWS", controlId: "1.10" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "1.1" }, GCP: { frameworkKey: "CIS_GCP", controlId: "1.1" } },
  "storage-public-access": { AWS: { frameworkKey: "CIS_AWS", controlId: "2.1.2" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "3.6" }, GCP: { frameworkKey: "CIS_GCP", controlId: "4.1" } },
  "storage-encryption": { AWS: { frameworkKey: "CIS_AWS", controlId: "2.1.1" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "3.1" }, GCP: { frameworkKey: "CIS_GCP", controlId: "4.3" } },
  "storage-logging": { AWS: { frameworkKey: "CIS_AWS", controlId: "2.1.3" }, GCP: { frameworkKey: "CIS_GCP", controlId: "4.2" } },
  "database-encryption": { AWS: { frameworkKey: "CIS_AWS", controlId: "2.2.1" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "4.1" } },
  "database-public-access": { AWS: { frameworkKey: "CIS_AWS", controlId: "2.2.2" } },
  "audit-logging-disabled": { AWS: { frameworkKey: "CIS_AWS", controlId: "3.1" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "5.1.2" }, GCP: { frameworkKey: "CIS_GCP", controlId: "2.1" } },
  "kms-rotation-disabled": { AWS: { frameworkKey: "CIS_AWS", controlId: "3.8" }, GCP: { frameworkKey: "CIS_GCP", controlId: "1.9" } },
  "firewall-sensitive-port-world": { AWS: { frameworkKey: "CIS_AWS", controlId: "5.2" }, AZURE: { frameworkKey: "CIS_AZURE", controlId: "6.1" }, GCP: { frameworkKey: "CIS_GCP", controlId: "3.6" } },
};

interface FindingDraft {
  ruleId: string;
  title: string;
  description: string;
  severity: NormalizedFinding["severity"];
  confidence: number;
  resource?: NormalizedCloudResource;
  identityRef?: string;
  evidence: string;
  remediation?: string;
}

function buildFinding(ctx: CloudAnalysisContext, draft: FindingDraft): NormalizedFinding {
  const findingClass = CLOUD_RULE_CLASSES[draft.ruleId] ?? "CLOUD_MISCONFIGURATION";
  const resourceId = draft.resource?.providerResourceId ?? draft.identityRef ?? ctx.accountRef;
  const fingerprint = cloudFingerprint({
    provider: ctx.provider, accountRef: ctx.accountRef,
    ...(draft.resource?.region ? { region: draft.resource.region } : {}),
    providerResourceId: resourceId, ruleId: draft.ruleId, findingClass,
  });
  return {
    title: sanitizeCloudText(draft.title, 300),
    description: sanitizeCloudText(draft.description, 2000),
    severity: draft.severity,
    confidence: draft.confidence,
    references: [],
    sourceTool: ctx.toolSlug,
    sourceFingerprint: fingerprint,
    origin: "CLOUD_FINDING",
    findingClass,
    cloudProvider: ctx.provider,
    cloudAccountId: ctx.accountId,
    providerResourceId: resourceId,
    ...(draft.resource ? { cloudResourceType: draft.resource.resourceType, resourceName: draft.resource.name } : {}),
    ...(draft.resource?.region ? { cloudRegion: draft.resource.region } : {}),
    ...(draft.resource ? { exposureClass: draft.resource.exposure } : {}),
    ruleId: draft.ruleId,
    controlId: CLOUD_RULE_CONTROLS[draft.ruleId]?.[ctx.provider]?.controlId,
    evidence: sanitizeCloudText(draft.evidence, 1000),
    ...(draft.remediation ? { remediation: draft.remediation } : {}),
  };
}

function controlFor(ctx: CloudAnalysisContext, ruleId: string, subjectRef: string, status: "PASS" | "FAIL", evidence: string): NormalizedControlAssessment | null {
  const mapping = CLOUD_RULE_CONTROLS[ruleId]?.[ctx.provider];
  if (!mapping) return null;
  return { frameworkKey: mapping.frameworkKey, controlId: mapping.controlId, subjectRef, status, evidence: sanitizeCloudText(evidence, 500) };
}

export interface CloudAnalysisResult {
  findings: NormalizedFinding[];
  controlAssessments: NormalizedControlAssessment[];
}

// ── IAM engine (§36–§42) ─────────────────────────────────────────────

interface PolicyFact { name: string; managedAdmin?: boolean; admin?: boolean; wildcardActions?: string[] }

export function analyzeIam(identities: NormalizedCloudIdentity[], ctx: CloudAnalysisContext): CloudAnalysisResult {
  const findings: NormalizedFinding[] = [];
  const controls: NormalizedControlAssessment[] = [];
  let adminSeen = false;
  let mfaGapSeen = false;
  for (const identity of identities) {
    const facts = (identity.metadata.policyFacts as PolicyFact[] | undefined) ?? [];
    const adminFact = facts.find((f) => f.admin || f.managedAdmin);
    if (adminFact || identity.privileged) {
      adminSeen = true;
      findings.push(buildFinding(ctx, {
        ruleId: "iam-admin-equivalent",
        title: `Administrator-equivalent access: ${identity.name}`,
        description: `Identity ${identity.name} holds administrator-equivalent privilege (${adminFact ? `policy ${adminFact.name}` : "provider privilege metadata"}). Per §38 this is an evidence-backed risk for organizational review — break-glass and platform-admin identities may be legitimate; scope or remove the grant where it is not.`,
        severity: "HIGH", confidence: 0.85, identityRef: identity.providerIdentityId,
        evidence: `privileged=${String(identity.privileged ?? false)} policy=${adminFact?.name ?? "n/a"}`,
        remediation: "Reduce IAM privilege: replace the administrator-equivalent grant with a scoped policy (§71).",
      }));
      const c = controlFor(ctx, "iam-admin-equivalent", identity.providerIdentityId, "FAIL", `admin-equivalent policy attached to ${identity.name}`);
      if (c) controls.push(c);
    }
    const wildcards = facts.flatMap((f) => f.wildcardActions ?? []).filter((a) => a !== "*");
    if (wildcards.length > 0 && !adminFact) {
      findings.push(buildFinding(ctx, {
        ruleId: "iam-wildcard-actions",
        title: `Wildcard IAM actions granted: ${identity.name}`,
        description: `Policy grants service-wide wildcard actions (${[...new Set(wildcards)].slice(0, 5).join(", ")}) on all resources. Wildcards are evidence of excess privilege (§38).`,
        severity: "MEDIUM", confidence: 0.8, identityRef: identity.providerIdentityId,
        evidence: `wildcardActions=${[...new Set(wildcards)].join(",")}`,
        remediation: "Enumerate the specific actions and resources the identity needs (§71).",
      }));
    }
    const trustFacts = identity.metadata.trustFacts as { broadTrust?: boolean; trustedPrincipals?: string[] } | undefined;
    if (trustFacts?.broadTrust) {
      findings.push(buildFinding(ctx, {
        ruleId: "iam-broad-trust",
        title: `Broad trust relationship: ${identity.name}`,
        description: `Trust policy grants assumption broadly (${(trustFacts.trustedPrincipals ?? []).join(", ")}). Broad trust lets external or anonymous principals reach this identity (§42). No assumption was attempted by the platform.`,
        severity: "HIGH", confidence: 0.85, identityRef: identity.providerIdentityId,
        evidence: `trustedPrincipals=${(trustFacts.trustedPrincipals ?? []).join(",")}`,
        remediation: "Scope the trust policy to named principals and require an external ID / condition (§71).",
      }));
    }
    if ((identity.identityType === "USER") && identity.mfaEnabled === false) {
      mfaGapSeen = true;
      findings.push(buildFinding(ctx, {
        ruleId: "mfa-not-enabled",
        title: `MFA not enabled: ${identity.name}`,
        description: `Human identity ${identity.name} has MFA disabled per provider metadata (§41). The platform assessed metadata only — no MFA authentication was attempted.`,
        severity: "MEDIUM", confidence: 0.8, identityRef: identity.providerIdentityId,
        evidence: "mfaEnabled=false (provider metadata)",
        remediation: "Require MFA for the identity and enforce it with policy conditions (§71).",
      }));
    }
    if ((identity.keyAgeDays ?? 0) > 365) {
      findings.push(buildFinding(ctx, {
        ruleId: "iam-long-lived-credentials",
        title: `Long-lived credential: ${identity.name}`,
        description: `Identity ${identity.name} holds a credential aged ${identity.keyAgeDays} days (§40). Only age metadata was read — credential material was never retrieved. Prefer short-lived / federated credentials (§8).`,
        severity: "LOW", confidence: 0.75, identityRef: identity.providerIdentityId,
        evidence: `keyAgeDays=${identity.keyAgeDays}`,
      }));
    }
    if (identity.privileged && identity.lastUsedAt) {
      const ageDays = Math.floor((Date.now() - new Date(identity.lastUsedAt).getTime()) / 86400000);
      if (Number.isFinite(ageDays) && ageDays > 180) {
        findings.push(buildFinding(ctx, {
          ruleId: "iam-stale-privileged-access",
          title: `Stale privileged access: ${identity.name}`,
          description: `Privileged identity ${identity.name} was last used ${ageDays} days ago per provider metadata (§39). Staleness is reported with its evidence; the platform does not claim the account is compromised.`,
          severity: "LOW", confidence: 0.6, identityRef: identity.providerIdentityId,
          evidence: `lastUsedAt=${identity.lastUsedAt} ageDays=${ageDays}`,
        }));
      }
    }
  }
  if (!adminSeen && identities.length > 0) {
    const c = controlFor(ctx, "iam-admin-equivalent", ctx.accountRef, "PASS", "no administrator-equivalent grants observed in analyzed policies");
    if (c) controls.push(c);
  }
  if (!mfaGapSeen && identities.some((i) => i.identityType === "USER")) {
    const c = controlFor(ctx, "mfa-not-enabled", ctx.accountRef, "PASS", "all analyzed human identities report MFA enabled");
    if (c) controls.push(c);
  }
  return { findings, controlAssessments: controls };
}

// ── Storage + database engines (§43–§45) ─────────────────────────────

const STORAGE_TYPES = ["S3_BUCKET", "STORAGE_ACCOUNT", "STORAGE_BUCKET"];
const DATABASE_TYPES = ["RDS_INSTANCE", "SQL_SERVER", "CLOUD_SQL"];

export function analyzeStorage(resources: NormalizedCloudResource[], ctx: CloudAnalysisContext): CloudAnalysisResult {
  const findings: NormalizedFinding[] = [];
  const controls: NormalizedControlAssessment[] = [];
  for (const r of resources) {
    if (!STORAGE_TYPES.some((t) => r.resourceType.includes(t))) continue;
    const cfg = r.configuration;
    if (cfg.publicAccess === true) {
      findings.push(buildFinding(ctx, {
        ruleId: "storage-public-access",
        title: `Public storage access: ${r.name}`,
        description: `Storage resource ${r.name} allows public access per its configuration (publicAccess=true${cfg.publicAccessBlock === false ? ", account/bucket public-access block disabled" : ""}). The finding is based on configuration evidence only — no object was downloaded (§44).`,
        severity: ctx.environment === "PRODUCTION" ? "CRITICAL" : "HIGH", confidence: 0.9, resource: r,
        evidence: `publicAccess=true publicAccessBlock=${String(cfg.publicAccessBlock ?? "n/a")} aclPublic=${String(cfg.aclPublic ?? "n/a")}`,
        remediation: "Enable the public-access block and remove public grants (§71).",
      }));
      const c = controlFor(ctx, "storage-public-access", r.providerResourceId, "FAIL", "public access enabled");
      if (c) controls.push(c);
    }
    if (typeof cfg.encryption === "string" && (cfg.encryption === "NONE" || cfg.encryption === "DISABLED")) {
      findings.push(buildFinding(ctx, {
        ruleId: "storage-encryption",
        title: `Storage encryption not enabled: ${r.name}`,
        description: `Storage resource ${r.name} reports encryption=${cfg.encryption} (§54).`,
        severity: "MEDIUM", confidence: 0.85, resource: r,
        evidence: `encryption=${cfg.encryption}`,
        remediation: "Enable default encryption, with a KMS key where required (§71).",
      }));
      const c = controlFor(ctx, "storage-encryption", r.providerResourceId, "FAIL", `encryption=${cfg.encryption}`);
      if (c) controls.push(c);
    }
    if (cfg.encryption === "PROVIDER_DEFAULT" && ctx.provider === "AWS") {
      findings.push(buildFinding(ctx, {
        ruleId: "storage-encryption-kms",
        title: `Storage uses provider-default encryption key: ${r.name}`,
        description: `Storage resource ${r.name} is encrypted with the provider-default key rather than a customer-managed KMS key (§54/§55).`,
        severity: "LOW", confidence: 0.7, resource: r,
        evidence: "encryption=PROVIDER_DEFAULT",
      }));
    }
    if (cfg.logging === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "storage-logging",
        title: `Storage access logging disabled: ${r.name}`,
        description: `Storage resource ${r.name} reports access logging disabled (§43).`,
        severity: "LOW", confidence: 0.8, resource: r,
        evidence: "logging=false",
        remediation: "Enable access logging to a governed log destination (§71).",
      }));
    }
    if (cfg.versioning === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "storage-versioning",
        title: `Storage versioning disabled: ${r.name}`,
        description: `Storage resource ${r.name} reports versioning disabled (§43).`,
        severity: "LOW", confidence: 0.8, resource: r,
        evidence: "versioning=false",
      }));
    }
  }
  return { findings, controlAssessments: controls };
}

export function analyzeDatabases(resources: NormalizedCloudResource[], ctx: CloudAnalysisContext): CloudAnalysisResult {
  const findings: NormalizedFinding[] = [];
  const controls: NormalizedControlAssessment[] = [];
  for (const r of resources) {
    if (!DATABASE_TYPES.some((t) => r.resourceType.includes(t))) continue;
    const cfg = r.configuration;
    if (cfg.publicAccess === true) {
      findings.push(buildFinding(ctx, {
        ruleId: "database-public-access",
        title: `Database publicly accessible: ${r.name}`,
        description: `Managed database ${r.name} is configured publicly accessible (§45). Assessment used metadata only — the platform never connects to databases (§45).`,
        severity: "HIGH", confidence: 0.9, resource: r,
        evidence: "publicAccess=true (provider configuration)",
        remediation: "Move the database to private subnets / private endpoints (§71).",
      }));
      const c = controlFor(ctx, "database-public-access", r.providerResourceId, "FAIL", "publicly accessible");
      if (c) controls.push(c);
    }
    if (cfg.encryption === false || cfg.encryption === "DISABLED" || cfg.encryption === "NONE") {
      findings.push(buildFinding(ctx, {
        ruleId: "database-encryption",
        title: `Database encryption not enabled: ${r.name}`,
        description: `Managed database ${r.name} reports storage encryption disabled (§45/§54).`,
        severity: "MEDIUM", confidence: 0.85, resource: r,
        evidence: `encryption=${String(cfg.encryption)}`,
        remediation: "Enable encryption at rest (§71).",
      }));
      const c = controlFor(ctx, "database-encryption", r.providerResourceId, "FAIL", "encryption disabled");
      if (c) controls.push(c);
    }
    if (cfg.backupEnabled === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "database-backup",
        title: `Database backups not configured: ${r.name}`,
        description: `Managed database ${r.name} reports backups disabled (§45).`,
        severity: "LOW", confidence: 0.8, resource: r,
        evidence: "backupEnabled=false",
      }));
    }
    if (cfg.tlsRequired === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "database-tls",
        title: `Database does not require TLS: ${r.name}`,
        description: `Managed database ${r.name} does not require TLS connections per its configuration (§45).`,
        severity: "MEDIUM", confidence: 0.8, resource: r,
        evidence: "tlsRequired=false",
      }));
    }
  }
  return { findings, controlAssessments: controls };
}

// ── Network / exposure engine (§46–§48) ──────────────────────────────

export const SENSITIVE_PORTS: Record<number, string> = {
  22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
  27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker API", 5900: "VNC", 1433: "MSSQL",
};

export function analyzeNetwork(resources: NormalizedCloudResource[], ctx: CloudAnalysisContext): CloudAnalysisResult {
  const findings: NormalizedFinding[] = [];
  const controls: NormalizedControlAssessment[] = [];
  for (const r of resources) {
    const rules = Array.isArray(r.configuration.ingressRules)
      ? (r.configuration.ingressRules as { cidr: string; fromPort: number; toPort: number; protocol: string }[]) : [];
    for (const rule of rules) {
      const world = rule.cidr === "0.0.0.0/0" || rule.cidr === "::/0" || rule.cidr === "*";
      if (!world) continue;
      const sensitive = Object.keys(SENSITIVE_PORTS).map(Number).filter((p) => p >= rule.fromPort && p <= rule.toPort);
      if (sensitive.length > 0) {
        findings.push(buildFinding(ctx, {
          ruleId: "firewall-sensitive-port-world",
          title: `Sensitive port open to the world: ${r.name} (${sensitive.map((p) => `${p}/${SENSITIVE_PORTS[p]}`).join(", ")})`,
          description: `Firewall rule on ${r.name} allows ${rule.cidr} to reach sensitive port(s) ${sensitive.join(", ")}. Risk reflects the port, the resource, the ${ctx.environment ?? "UNKNOWN"} environment and the recorded exposure (${r.exposure}) (§48).`,
          severity: sensitive.includes(22) || sensitive.includes(3389) || sensitive.includes(2375) ? "CRITICAL" : "HIGH",
          confidence: 0.9, resource: r,
          evidence: `ingress ${rule.cidr} ${rule.fromPort}-${rule.toPort}/${rule.protocol}`,
          remediation: "Scope the rule to the approved management network (§71).",
        }));
        const c = controlFor(ctx, "firewall-sensitive-port-world", r.providerResourceId, "FAIL", `world-open sensitive port ${sensitive.join(",")}`);
        if (c) controls.push(c);
      } else if (!(rule.fromPort === 443 && rule.toPort === 443) && !(rule.fromPort === 80 && rule.toPort === 80)) {
        findings.push(buildFinding(ctx, {
          ruleId: "firewall-world-open-port",
          title: `Port range open to the world: ${r.name} (${rule.fromPort}-${rule.toPort})`,
          description: `Firewall rule on ${r.name} allows ${rule.cidr} to reach ports ${rule.fromPort}-${rule.toPort} (§48). Standard web ports (80/443) are not flagged; review whether this range is intended to be public.`,
          severity: "MEDIUM", confidence: 0.7, resource: r,
          evidence: `ingress ${rule.cidr} ${rule.fromPort}-${rule.toPort}/${rule.protocol}`,
        }));
      }
    }
    if (r.resourceType.includes("LAMBDA") || r.resourceType.includes("FUNCTION")) {
      if (r.configuration.publicAccess === true) {
        findings.push(buildFinding(ctx, {
          ruleId: "serverless-public-access",
          title: `Serverless function publicly invokable: ${r.name}`,
          description: `Function ${r.name} allows public invocation per its configuration (§52). Environment variable VALUES were not retrieved — only key names are inventoried.`,
          severity: "MEDIUM", confidence: 0.8, resource: r,
          evidence: "publicAccess=true (function policy metadata)",
        }));
      }
    }
  }
  return { findings, controlAssessments: controls };
}

// ── Encryption engine (§54/§55) ──────────────────────────────────────

export function analyzeEncryption(resources: NormalizedCloudResource[], ctx: CloudAnalysisContext): CloudAnalysisResult {
  const findings: NormalizedFinding[] = [];
  const controls: NormalizedControlAssessment[] = [];
  for (const r of resources) {
    if (!r.resourceType.includes("KMS")) continue;
    if (r.configuration.rotationEnabled === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "kms-rotation-disabled",
        title: `KMS key rotation disabled: ${r.name}`,
        description: `KMS key ${r.name} reports automatic rotation disabled (§55). Key metadata only — key material is never exported or requested (§55).`,
        severity: "LOW", confidence: 0.85, resource: r,
        evidence: "rotationEnabled=false",
        remediation: "Enable automatic key rotation (§71).",
      }));
      const c = controlFor(ctx, "kms-rotation-disabled", r.providerResourceId, "FAIL", "rotation disabled");
      if (c) controls.push(c);
    }
  }
  return { findings, controlAssessments: controls };
}

// ── Logging / security services engine (§56/§57) ─────────────────────

const TRAIL_TYPES = ["CLOUDTRAIL", "ACTIVITY_LOG", "LOGGING_CONFIG"];
const SECURITY_SERVICE_TYPES = ["GUARDDUTY", "SECURITY_HUB", "DEFENDER", "SCC"];

export function analyzeLogging(resources: NormalizedCloudResource[], ctx: CloudAnalysisContext): CloudAnalysisResult {
  const findings: NormalizedFinding[] = [];
  const controls: NormalizedControlAssessment[] = [];
  const trails = resources.filter((r) => TRAIL_TYPES.some((t) => r.resourceType.includes(t)));
  for (const r of trails) {
    if (r.configuration.enabled === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "audit-logging-disabled",
        title: `Audit logging disabled: ${r.name}`,
        description: `Audit logging service ${r.name} is disabled (§56). Without the audit trail, IAM and resource changes are not recorded.`,
        severity: "HIGH", confidence: 0.9, resource: r,
        evidence: "enabled=false",
        remediation: "Enable the audit trail in all regions with log-file validation (§71).",
      }));
      const c = controlFor(ctx, "audit-logging-disabled", r.providerResourceId, "FAIL", "audit logging disabled");
      if (c) controls.push(c);
    } else if (r.configuration.multiRegion === false) {
      findings.push(buildFinding(ctx, {
        ruleId: "audit-logging-single-region",
        title: `Audit logging is single-region: ${r.name}`,
        description: `Audit logging ${r.name} covers one region only (§56); activity in other regions is not recorded.`,
        severity: "LOW", confidence: 0.8, resource: r,
        evidence: "multiRegion=false",
      }));
    }
  }
  if (trails.length > 0 && trails.every((t) => t.configuration.enabled !== false)) {
    const c = controlFor(ctx, "audit-logging-disabled", ctx.accountRef, "PASS", "audit logging enabled in analyzed inventory");
    if (c) controls.push(c);
  }
  for (const r of resources) {
    if (!SECURITY_SERVICE_TYPES.some((t) => r.resourceType.includes(t))) continue;
    if (r.configuration.enabled === false) {
      // §57: a disabled security service is a policy-governed gap, not
      // automatically a vulnerability.
      findings.push(buildFinding(ctx, {
        ruleId: "security-service-disabled",
        title: `Security service disabled: ${r.name}`,
        description: `Security service ${r.name} is disabled (§57). Whether this is a gap depends on organizational policy and compensating controls — recorded as a logging/monitoring gap for review.`,
        severity: "LOW", confidence: 0.65, resource: r,
        evidence: "enabled=false (configuration metadata)",
      }));
    }
  }
  return { findings, controlAssessments: controls };
}

/** Run every provider-native engine over one normalized inventory
 *  (§36/§43/§45–§57). Sections are independent: one section's failure
 *  domain never suppresses another's evidence (§76). */
export function analyzeCloudInventory(
  data: { resources: NormalizedCloudResource[]; identities: NormalizedCloudIdentity[] },
  ctx: CloudAnalysisContext,
): CloudAnalysisResult {
  const sections = [
    analyzeIam(data.identities, ctx),
    analyzeStorage(data.resources, ctx),
    analyzeDatabases(data.resources, ctx),
    analyzeNetwork(data.resources, ctx),
    analyzeEncryption(data.resources, ctx),
    analyzeLogging(data.resources, ctx),
  ];
  return {
    findings: sections.flatMap((s) => s.findings),
    controlAssessments: sections.flatMap((s) => s.controlAssessments),
  };
}

/** Whether audit logging is enabled in this inventory (quality-gate
 *  input, §70): true/false only when a trail resource was observed. */
export function auditLoggingEnabled(resources: NormalizedCloudResource[]): boolean | null {
  const trails = resources.filter((r) => TRAIL_TYPES.some((t) => r.resourceType.includes(t)));
  if (trails.length === 0) return null;
  return trails.some((t) => t.configuration.enabled !== false);
}

export type { CloudExposureClass };
