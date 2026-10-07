/**
 * Prompt 14 — provider inventory (§13/§16–§19).
 *
 * Provider-native inventory adapters collect security-relevant
 * METADATA only: no object contents, no secret values, no key
 * material, no database rows (§13/§43/§52/§53/§55). Raw provider
 * payloads are untrusted input — they are size/depth-bounded and
 * normalized into bounded configuration facts the analyzers reason
 * over. Transports are read-only BY CONSTRUCTION: the interface has
 * no mutating method, and the read-only enforcement test (§93) fails
 * if a transport ever records a mutation call.
 */
import { createHash } from "node:crypto";
import type {
  CloudExposureClass, NormalizedCloudData, NormalizedCloudIdentity,
  NormalizedCloudRelationship, NormalizedCloudResource, NormalizedCloudSnapshot,
} from "../findings/finding.types";
import { cloudArr, cloudBool, cloudNum, cloudRec, cloudStr, hasBroadTrust, parseBoundedJson, parseIamPolicyDocument, redactSecretShapes, sanitizeCloudText, sanitizeStringMap } from "./guards";
import { EMPTY_CLOUD_SCOPE, isResourceInCloudScope, type CloudAccountRecord, type CloudProvider, type CloudScopeDef } from "./types";

/** Raw provider inventory payload (fixture shape mirrors each
 *  provider's describe/list responses, reduced to metadata). */
export interface RawCloudInventory {
  identity?: Record<string, unknown>;
  regions?: string[];
  resources?: Record<string, unknown>[];
  identities?: Record<string, unknown>[];
}

/** Read-only provider transport (§7/§93). Implementations call
 *  Describe/Get/List APIs ONLY. `mutationCalls` exists so the
 *  read-only test can prove ordinary assessments invoke none. */
export interface CloudInventoryTransport {
  readonly provider: CloudProvider;
  readonly mutationCalls: string[];
  validateIdentity(account: CloudAccountRecord): Promise<Record<string, unknown>>;
  fetchInventory(account: CloudAccountRecord, scope: CloudScopeDef): Promise<RawCloudInventory>;
}

export interface CloudConnectorDeps {
  accounts: { getById(id: string): Promise<CloudAccountRecord | null> };
  transports: Partial<Record<CloudProvider, CloudInventoryTransport>>;
}

/** Inert deps for plan-time registration (API): no account resolves and
 *  no transport is wired, so connectors honestly report
 *  NOT_CONFIGURED (§9). */
export const INERT_CLOUD_DEPS: CloudConnectorDeps = {
  accounts: { async getById() { return null; } },
  transports: {},
};

/** A transport backed by a recorded fixture payload (tests + controlled
 *  test accounts, §90–§92). Mutation methods do not exist; any attempt
 *  to record one fails the read-only test by construction. */
export function createFixtureCloudTransport(provider: CloudProvider, payload: RawCloudInventory): CloudInventoryTransport {
  return {
    provider,
    mutationCalls: [],
    async validateIdentity(account) {
      return { provider, externalAccountId: account.externalAccountId, ...(payload.identity ?? {}) };
    },
    async fetchInventory() {
      return payload;
    },
  };
}

const RESOURCE_TYPE_MAP: Record<CloudProvider, Record<string, string>> = {
  AWS: {
    s3_bucket: "AWS_S3_BUCKET", security_group: "AWS_SECURITY_GROUP", ec2_instance: "AWS_EC2_INSTANCE",
    rds_instance: "AWS_RDS_INSTANCE", kms_key: "AWS_KMS_KEY", cloudtrail: "AWS_CLOUDTRAIL",
    guardduty: "AWS_GUARDDUTY", securityhub: "AWS_SECURITY_HUB", lambda_function: "AWS_LAMBDA_FUNCTION",
    eks_cluster: "AWS_EKS_CLUSTER", ecr_repository: "AWS_ECR_REPOSITORY", secrets_manager_secret: "AWS_SECRETS_MANAGER_SECRET",
    iam_policy: "AWS_IAM_POLICY", load_balancer: "AWS_LOAD_BALANCER", vpc: "AWS_VPC",
  },
  AZURE: {
    storage_account: "AZURE_STORAGE_ACCOUNT", nsg: "AZURE_NSG", virtual_machine: "AZURE_VIRTUAL_MACHINE",
    sql_server: "AZURE_SQL_SERVER", key_vault: "AZURE_KEY_VAULT", aks_cluster: "AZURE_AKS_CLUSTER",
    container_registry: "AZURE_CONTAINER_REGISTRY", activity_log: "AZURE_ACTIVITY_LOG",
    defender: "AZURE_DEFENDER", function_app: "AZURE_FUNCTION_APP", virtual_network: "AZURE_VIRTUAL_NETWORK",
  },
  GCP: {
    storage_bucket: "GCP_STORAGE_BUCKET", firewall_rule: "GCP_FIREWALL_RULE", compute_instance: "GCP_COMPUTE_INSTANCE",
    sql_instance: "GCP_CLOUD_SQL", kms_key: "GCP_KMS_KEY", gke_cluster: "GCP_GKE_CLUSTER",
    artifact_registry: "GCP_ARTIFACT_REGISTRY", logging_config: "GCP_LOGGING_CONFIG",
    security_command_center: "GCP_SCC", cloud_function: "GCP_CLOUD_FUNCTION", vpc: "GCP_VPC",
  },
};

export function canonicalResourceType(provider: CloudProvider, rawType: string): string {
  return RESOURCE_TYPE_MAP[provider][rawType] ?? `${provider}_${rawType.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`;
}

/** Normalize one raw resource's config block into bounded security
 *  facts. Only the fields analyzers use survive; everything else —
 *  including any customer data a provider might echo — is dropped. */
function normalizeConfig(rawType: string, cfg: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const copy = (from: string, to: string = from) => { if (cfg[from] !== undefined) out[to] = cfg[from]; };
  // storage (§43)
  copy("publicAccess"); copy("publicAccessBlock"); copy("aclPublic"); copy("encryption"); copy("logging"); copy("versioning");
  // network (§46/§48)
  if (Array.isArray(cfg.ingress)) out.ingressRules = cloudArr(cfg.ingress as unknown).map((r) => ({
    cidr: cloudStr(r.cidr) ?? cloudStr(r.sourceAddressPrefix) ?? cloudStr(r.sourceRange) ?? "",
    fromPort: cloudNum(r.fromPort) ?? cloudNum(r.destinationPort) ?? 0,
    toPort: cloudNum(r.toPort) ?? cloudNum(r.destinationPort) ?? cloudNum(r.fromPort) ?? 0,
    protocol: cloudStr(r.protocol) ?? "tcp",
  })).slice(0, 200);
  copy("publicIp"); copy("internetFacing", "internetFacing");
  // database (§45)
  copy("publiclyAccessible", "publicAccess"); copy("backupEnabled"); copy("tlsRequired");
  // logging / security services (§56/§57)
  copy("enabled"); copy("multiRegion"); copy("isLogging", "enabled");
  // kms (§55) — metadata only; key material is never a config field
  copy("rotationEnabled"); copy("keyState");
  // serverless (§52) — identity + runtime + exposure; env VALUES never copied
  copy("runtime"); copy("identityRef"); copy("envKeys");
  // cluster / registry (§50/§51)
  copy("clusterName"); copy("version"); copy("registryName"); copy("endpointPublicAccess");
  // secret-manager metadata (§53) — existence + rotation config only
  copy("secretName", "name");
  return out;
}

/** Evidence-based exposure classification (§47): PUBLIC only when the
 *  configuration itself proves internet reachability; possible when a
 *  public path exists but a control may intervene; never fabricated. */
export function classifyExposure(resourceType: string, config: Record<string, unknown>): CloudExposureClass {
  if (config.publicAccess === true) return "PUBLIC";
  if (typeof config.publicIp === "string" && config.publicIp.length > 0) return "PUBLIC";
  if (config.internetFacing === true) return "PUBLIC";
  const rules = Array.isArray(config.ingressRules) ? (config.ingressRules as { cidr: string }[]) : [];
  if (rules.some((r) => r.cidr === "0.0.0.0/0" || r.cidr === "::/0" || r.cidr === "*")) return "PUBLIC";
  if (config.endpointPublicAccess === true) return "INTERNET_REACHABLE_POSSIBLE";
  if (config.publicAccess === false || config.publiclyAccessible === false) return "PRIVATE";
  if (resourceType.includes("VPC") || resourceType.includes("VIRTUAL_NETWORK")) return "PRIVATE";
  return "UNKNOWN";
}

/** Normalize a raw provider inventory payload into the bounded
 *  normalized model (§14/§36/§15). Scope filtering happens here: out-
 *  of-scope resources are returned flagged, never silently dropped —
 *  the store records them OUT_OF_SCOPE and analyzers skip them. */
export function normalizeProviderInventory(
  provider: CloudProvider,
  raw: RawCloudInventory,
  ctx: { accountId: string; accountRef: string; scope?: CloudScopeDef; toolSlug: string },
): NormalizedCloudData & { outOfScope: NormalizedCloudResource[]; snapshot: NormalizedCloudSnapshot } {
  const scope = ctx.scope ?? EMPTY_CLOUD_SCOPE;
  const resources: NormalizedCloudResource[] = [];
  const outOfScope: NormalizedCloudResource[] = [];
  const relationships: NormalizedCloudRelationship[] = [];
  for (const r of (raw.resources ?? []).slice(0, 5000)) {
    const rawType = cloudStr(r.type) ?? "unknown";
    const providerResourceId = cloudStr(r.id) ?? cloudStr(r.arn) ?? cloudStr(r.name) ?? "";
    if (!providerResourceId) continue;
    const config = normalizeConfig(rawType, cloudRec(r.config));
    const resourceType = canonicalResourceType(provider, rawType);
    const resource: NormalizedCloudResource = {
      provider,
      resourceType,
      providerResourceId,
      name: sanitizeCloudText(cloudStr(r.name) ?? providerResourceId, 300),
      ...(cloudStr(r.region) ? { region: cloudStr(r.region) } : {}),
      ...(cloudStr(r.zone) ? { zone: cloudStr(r.zone) } : {}),
      tags: Object.fromEntries(Object.entries(sanitizeStringMap(r.tags)).map(([k, v]) => [k, redactSecretShapes(v)])),
      configuration: config,
      exposure: classifyExposure(resourceType, config),
      source: ctx.toolSlug,
    };
    if (!isResourceInCloudScope(resource, scope)) { outOfScope.push(resource); continue; }
    resources.push(resource);
    relationships.push({ fromType: "ACCOUNT", fromRef: ctx.accountRef, toType: "RESOURCE", toRef: providerResourceId, relationship: "CONTAINS", evidence: `${provider} inventory` });
    if (resource.region) relationships.push({ fromType: "REGION", fromRef: resource.region, toType: "RESOURCE", toRef: providerResourceId, relationship: "CONTAINS" });
    if (typeof config.identityRef === "string") {
      relationships.push({ fromType: "RESOURCE", fromRef: providerResourceId, toType: "IDENTITY", toRef: config.identityRef, relationship: "ASSUMES", evidence: "workload identity configuration" });
    }
    if (resourceType.includes("EKS") || resourceType.includes("AKS") || resourceType.includes("GKE")) {
      relationships.push({ fromType: "RESOURCE", fromRef: providerResourceId, toType: "CLUSTER", toRef: cloudStr(config.clusterName) ?? resource.name, relationship: "MAPS_TO", evidence: "managed Kubernetes service (§50)" });
    }
    if (resourceType.includes("ECR") || resourceType.includes("CONTAINER_REGISTRY") || resourceType.includes("ARTIFACT_REGISTRY")) {
      relationships.push({ fromType: "RESOURCE", fromRef: providerResourceId, toType: "RESOURCE", toRef: providerResourceId, relationship: "MAPS_TO", evidence: "container registry (§51)" });
    }
  }
  const identities: NormalizedCloudIdentity[] = [];
  for (const i of (raw.identities ?? []).slice(0, 5000)) {
    const idType = (cloudStr(i.type) ?? "user").toUpperCase();
    const identityType = (["USER", "ROLE", "GROUP", "SERVICE_ACCOUNT", "MANAGED_IDENTITY", "POLICY"].includes(idType) ? idType : "USER") as NormalizedCloudIdentity["identityType"];
    const keys = cloudArr(i.accessKeys as unknown);
    const oldestKey = keys.length > 0 ? Math.max(...keys.map((k) => cloudNum(k.ageDays) ?? 0)) : undefined;
    // IAM policy documents are untrusted input (§36/§42): parsed under
    // hard caps into FACTS (wildcard grants, admin equivalence, broad
    // trust) — the document itself is never stored or evaluated.
    const policyFacts = cloudArr(i.attachedPolicies as unknown).map((p) => {
      const parsed = p.document !== undefined ? parseIamPolicyDocument(p.document) : null;
      return {
        name: cloudStr(p.name) ?? "",
        managedAdmin: (cloudStr(p.name) ?? "").toLowerCase().includes("administratoraccess"),
        ...(parsed ? { admin: parsed.isAdministratorEquivalent, wildcardActions: parsed.wildcardActions } : {}),
      };
    }).slice(0, 100);
    const trust = i.trustPolicy !== undefined ? parseIamPolicyDocument(i.trustPolicy) : null;
    const derivedPrivileged = cloudBool(i.privileged) ?? (policyFacts.some((f) => f.admin || f.managedAdmin) || undefined);
    identities.push({
      provider,
      identityType,
      providerIdentityId: cloudStr(i.id) ?? cloudStr(i.arn) ?? cloudStr(i.name) ?? "",
      name: sanitizeCloudText(cloudStr(i.name) ?? "", 300),
      ...(derivedPrivileged !== undefined ? { privileged: derivedPrivileged } : {}),
      ...(i.privilegeEvidence ? { privilegeEvidence: cloudRec(i.privilegeEvidence) } : {}),
      ...(cloudBool(i.mfaEnabled) !== undefined ? { mfaEnabled: cloudBool(i.mfaEnabled) } : {}),
      ...(cloudStr(i.lastUsed) ? { lastUsedAt: cloudStr(i.lastUsed) } : {}),
      ...(cloudStr(i.lastSignIn) ? { lastSignInAt: cloudStr(i.lastSignIn) } : {}),
      ...(oldestKey !== undefined && oldestKey > 0 ? { keyAgeDays: oldestKey } : {}),
      metadata: {
        attachedPolicies: policyFacts.map((f) => f.name).filter(Boolean),
        policyFacts,
        ...(trust ? { trustFacts: { trustedPrincipals: trust.trustedPrincipals, broadTrust: hasBroadTrust(trust) } } : {}),
      },
    });
    const iid = identities[identities.length - 1]!;
    if (iid.providerIdentityId) {
      relationships.push({ fromType: "ACCOUNT", fromRef: ctx.accountRef, toType: "IDENTITY", toRef: iid.providerIdentityId, relationship: "CONTAINS" });
      for (const p of cloudArr(i.attachedPolicies as unknown)) {
        const pname = cloudStr(p.name);
        if (pname) relationships.push({ fromType: "IDENTITY", fromRef: iid.providerIdentityId, toType: "POLICY", toRef: pname, relationship: "GRANTS", evidence: "attached policy" });
      }
    }
  }
  const regions = [...new Set([...(raw.regions ?? []), ...resources.map((r) => r.region).filter((x): x is string => !!x)])].sort();
  const resourceCounts: Record<string, number> = {};
  for (const r of resources) resourceCounts[r.resourceType] = (resourceCounts[r.resourceType] ?? 0) + 1;
  const hash = createHash("sha256").update(JSON.stringify(
    resources.map((r) => [r.providerResourceId, JSON.stringify(r.configuration)]).sort(),
  )).digest("hex");
  const snapshot: NormalizedCloudSnapshot = { provider, regions, resourceCounts, snapshotHash: hash };
  return { resources, identities, relationships, controlAssessments: [], riskPaths: [], outOfScope, snapshot };
}

/** Parse + normalize in one step for text payloads (fixture files /
 *  recorded provider responses). Bounded parse (§99) applies. */
export function parseProviderInventoryText(
  provider: CloudProvider, text: string,
  ctx: { accountId: string; accountRef: string; scope?: CloudScopeDef; toolSlug: string },
): ReturnType<typeof normalizeProviderInventory> {
  const raw = parseBoundedJson(text, { what: `${provider} inventory` }) as RawCloudInventory;
  return normalizeProviderInventory(provider, raw, ctx);
}

/** Drift comparison between two inventory snapshots (§64): added /
 *  removed resources and exposure / encryption / logging changes.
 *  A change is an observation — never an automatic malicious verdict. */
export interface CloudDriftItem {
  kind: "RESOURCE_ADDED" | "RESOURCE_REMOVED" | "EXPOSURE_CHANGED" | "IAM_CHANGED" | "ENCRYPTION_CHANGED" | "LOGGING_CHANGED";
  resourceRef?: string;
  detail: string;
}

export function diffCloudInventories(
  previous: { resources: NormalizedCloudResource[]; identities: NormalizedCloudIdentity[] },
  current: { resources: NormalizedCloudResource[]; identities: NormalizedCloudIdentity[] },
): CloudDriftItem[] {
  const out: CloudDriftItem[] = [];
  const prevById = new Map(previous.resources.map((r) => [r.providerResourceId, r]));
  const curById = new Map(current.resources.map((r) => [r.providerResourceId, r]));
  for (const r of current.resources) {
    const p = prevById.get(r.providerResourceId);
    if (!p) { out.push({ kind: "RESOURCE_ADDED", resourceRef: r.providerResourceId, detail: `${r.resourceType} ${r.name} appeared in inventory` }); continue; }
    if (p.exposure !== r.exposure) out.push({ kind: "EXPOSURE_CHANGED", resourceRef: r.providerResourceId, detail: `exposure ${p.exposure} → ${r.exposure}` });
    if (JSON.stringify(p.configuration.encryption ?? null) !== JSON.stringify(r.configuration.encryption ?? null)) {
      out.push({ kind: "ENCRYPTION_CHANGED", resourceRef: r.providerResourceId, detail: `encryption configuration changed` });
    }
    if (JSON.stringify(p.configuration.logging ?? p.configuration.enabled ?? null) !== JSON.stringify(r.configuration.logging ?? r.configuration.enabled ?? null)) {
      out.push({ kind: "LOGGING_CHANGED", resourceRef: r.providerResourceId, detail: `logging configuration changed` });
    }
  }
  for (const r of previous.resources) {
    if (!curById.has(r.providerResourceId)) out.push({ kind: "RESOURCE_REMOVED", resourceRef: r.providerResourceId, detail: `${r.resourceType} ${r.name} no longer in inventory — marked NOT_SEEN, history retained (§20)` });
  }
  const prevIds = new Set(previous.identities.map((i) => i.providerIdentityId));
  const curIds = new Set(current.identities.map((i) => i.providerIdentityId));
  for (const i of current.identities) if (!prevIds.has(i.providerIdentityId)) out.push({ kind: "IAM_CHANGED", resourceRef: i.providerIdentityId, detail: `identity ${i.name} appeared` });
  for (const i of previous.identities) if (!curIds.has(i.providerIdentityId)) out.push({ kind: "IAM_CHANGED", resourceRef: i.providerIdentityId, detail: `identity ${i.name} no longer present` });
  for (const i of current.identities) {
    const p = previous.identities.find((x) => x.providerIdentityId === i.providerIdentityId);
    if (p && p.privileged !== i.privileged) out.push({ kind: "IAM_CHANGED", resourceRef: i.providerIdentityId, detail: `identity ${i.name} privilege ${String(p.privileged ?? false)} → ${String(i.privileged ?? false)}` });
  }
  return out;
}
