/**
 * Prompt 14 — CSPM tool report parsers (§23–§33).
 *
 * Prowler / ScoutSuite / CloudMapper / Steampipe / ROADtools outputs
 * are untrusted input: bounded, shape-checked, and mapped onto the
 * CANONICAL rule catalog so a tool observation and the provider-
 * native analyzer observation of the same issue share one fingerprint
 * and merge (§60). PASS results never become findings (§23); severity
 * is never blindly trusted (§60) — tool severity is kept as evidence
 * and the canonical severity comes from the governed mapping.
 */
import type { NormalizedCloudData, NormalizedFinding } from "../findings/finding.types";
import { CLOUD_RULE_CLASSES } from "./analysis";
import { cloudFingerprint } from "./correlation";
import { cloudArr, cloudRec, cloudStr, parseBoundedJson, sanitizeCloudText } from "./guards";
import { cloudEndpointVerdict } from "./guards";
import type { CloudProvider } from "./types";

export interface CloudSecParserContext {
  toolSlug: string;
  provider?: CloudProvider;
  accountId?: string;
  accountRef?: string;
}

/** The parsed payload every Prompt 14 adapter produces: canonical
 *  findings plus the normalized cloud inventory payload (§14). */
export interface ParsedCloudSec {
  findings: NormalizedFinding[];
  cloud?: NormalizedCloudData;
  metrics: Record<string, number>;
}

export function emptyParsedCloudSec(metrics: Record<string, number> = {}): ParsedCloudSec {
  return { findings: [], metrics };
}

/** Canonical-rule inference from a tool check id (§60): known check
 *  families map to analyzer rules; anything else keeps the tool's own
 *  rule id (still fingerprint-stable, never merged speculatively). */
export function canonicalCloudRule(checkId: string, service?: string): string {
  const id = checkId.toLowerCase();
  const svc = (service ?? "").toLowerCase();
  if ((svc.includes("s3") || svc.includes("storage")) && (id.includes("public") || id.includes("acl"))) return "storage-public-access";
  if ((svc.includes("s3") || svc.includes("storage")) && id.includes("encrypt")) return "storage-encryption";
  if ((svc.includes("s3") || svc.includes("storage")) && id.includes("logging")) return "storage-logging";
  if ((svc.includes("rds") || svc.includes("sql") || svc.includes("database")) && id.includes("public")) return "database-public-access";
  if ((svc.includes("rds") || svc.includes("sql") || svc.includes("database")) && id.includes("encrypt")) return "database-encryption";
  if ((id.includes("securitygroup") || id.includes("security_group") || id.includes("nsg") || id.includes("firewall")) && (id.includes("22") || id.includes("3389") || id.includes("ssh") || id.includes("rdp") || id.includes("ingress"))) return "firewall-sensitive-port-world";
  if (id.includes("admin") && (svc.includes("iam") || id.includes("iam"))) return "iam-admin-equivalent";
  if (id.includes("privileged") && (svc.includes("iam") || id.includes("entra"))) return "iam-admin-equivalent";
  if (id.includes("high-permissions") || id.includes("overprivileged")) return "iam-wildcard-actions";
  if (id.includes("mfa")) return "mfa-not-enabled";
  if ((id.includes("cloudtrail") || id.includes("audit")) && (id.includes("log") || id.includes("trail"))) return "audit-logging-disabled";
  if (id.includes("kms") && id.includes("rotat")) return "kms-rotation-disabled";
  return checkId;
}

const CANONICAL_SEVERITY: Record<string, NormalizedFinding["severity"]> = {
  "storage-public-access": "HIGH",
  "database-public-access": "HIGH",
  "firewall-sensitive-port-world": "HIGH",
  "iam-admin-equivalent": "HIGH",
  "audit-logging-disabled": "HIGH",
  "storage-encryption": "MEDIUM",
  "database-encryption": "MEDIUM",
  "mfa-not-enabled": "MEDIUM",
  "storage-logging": "LOW",
  "kms-rotation-disabled": "LOW",
};

function findingFromCheck(ctx: CloudSecParserContext, input: {
  checkId: string; title: string; resourceId: string; region?: string; service?: string;
  severity?: string; evidence?: string; description?: string;
}): NormalizedFinding {
  const provider = ctx.provider ?? "AWS";
  const ruleId = canonicalCloudRule(input.checkId, input.service);
  const findingClass = CLOUD_RULE_CLASSES[ruleId] ?? "CLOUD_MISCONFIGURATION";
  const fingerprint = cloudFingerprint({
    provider, accountRef: ctx.accountRef ?? "unknown-account",
    ...(input.region ? { region: input.region } : {}),
    providerResourceId: input.resourceId, ruleId, findingClass,
  });
  return {
    title: sanitizeCloudText(input.title, 300),
    description: sanitizeCloudText(input.description ?? `${ctx.toolSlug} reported check ${input.checkId} on ${input.resourceId}.`, 2000),
    severity: CANONICAL_SEVERITY[ruleId] ?? mapToolSeverity(input.severity),
    confidence: 0.8,
    references: [],
    sourceTool: ctx.toolSlug,
    sourceFingerprint: fingerprint,
    origin: "CLOUD_FINDING",
    findingClass,
    cloudProvider: provider,
    ...(ctx.accountId ? { cloudAccountId: ctx.accountId } : {}),
    providerResourceId: input.resourceId,
    ...(input.region ? { cloudRegion: input.region } : {}),
    ruleId,
    evidence: sanitizeCloudText(input.evidence ?? `check=${input.checkId} toolSeverity=${input.severity ?? "n/a"}`, 1000),
  };
}

export function mapToolSeverity(raw: string | undefined): NormalizedFinding["severity"] {
  switch ((raw ?? "").toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH": return "HIGH";
    case "MEDIUM": case "MODERATE": return "MEDIUM";
    case "LOW": return "LOW";
    default: return "INFORMATIONAL";
  }
}

/** Prowler (§23/§24): FAIL findings only — PASS/SKIP/manual become
 *  posture evidence upstream (control assessments), never findings. */
export function parseProwler(raw: unknown, ctx: CloudSecParserContext): NormalizedFinding[] {
  const rows = Array.isArray(raw) ? raw : cloudArr((raw as Record<string, unknown>)?.findings);
  const out: NormalizedFinding[] = [];
  for (const row of rows.slice(0, 5000)) {
    const status = (cloudStr(row.Status) ?? cloudStr(row.status) ?? "").toUpperCase();
    if (status !== "FAIL") continue; // PASS never becomes a finding (§23)
    const checkId = cloudStr(row.CheckID) ?? cloudStr(row.check_id) ?? cloudStr(row.CheckId) ?? "prowler-check";
    const resourceId = cloudStr(row.ResourceArn) ?? cloudStr(row.ResourceId) ?? cloudStr(row.resource_id) ?? cloudStr(row.ResourceName);
    if (!resourceId) continue;
    out.push(findingFromCheck(ctx, {
      checkId,
      title: cloudStr(row.CheckTitle) ?? cloudStr(row.check_title) ?? `Prowler: ${checkId}`,
      resourceId,
      ...(cloudStr(row.Region) ?? cloudStr(row.region) ? { region: (cloudStr(row.Region) ?? cloudStr(row.region))! } : {}),
      ...(cloudStr(row.ServiceName) ?? cloudStr(row.service) ? { service: (cloudStr(row.ServiceName) ?? cloudStr(row.service))! } : {}),
      ...(cloudStr(row.Severity) ?? cloudStr(row.severity) ? { severity: (cloudStr(row.Severity) ?? cloudStr(row.severity))! } : {}),
      evidence: `prowler ${checkId} status=FAIL account=${cloudStr(row.AccountId) ?? cloudStr(row.account_id) ?? "n/a"}`,
      ...(cloudStr(row.Description) ?? cloudStr(row.description) ? { description: (cloudStr(row.Description) ?? cloudStr(row.description))! } : {}),
    }));
  }
  return out;
}

export function parseProwlerText(text: string, ctx: CloudSecParserContext): NormalizedFinding[] {
  return parseProwler(parseBoundedJson(text, { what: "prowler report" }), ctx);
}

/** ScoutSuite (§26): rule results across services; rules with no
 *  flagged items produce nothing. */
export function parseScoutSuite(raw: unknown, ctx: CloudSecParserContext): NormalizedFinding[] {
  const root = cloudRec(raw);
  const out: NormalizedFinding[] = [];
  const services = cloudRec(root.services);
  for (const [service, svcRaw] of Object.entries(services)) {
    const findings = cloudRec(cloudRec(svcRaw).findings);
    for (const [ruleId, ruleRaw] of Object.entries(findings)) {
      const rule = cloudRec(ruleRaw);
      const items = Array.isArray(rule.items) ? rule.items : Array.isArray(rule.flagged_items) ? rule.flagged_items : [];
      for (const item of items.slice(0, 1000)) {
        const itemRec = cloudRec(item);
        const resourceId = cloudStr(itemRec.id) ?? cloudStr(itemRec.arn) ?? cloudStr(itemRec.path) ?? cloudStr(itemRec.resource_id);
        if (!resourceId) continue;
        out.push(findingFromCheck(ctx, {
          checkId: ruleId,
          title: cloudStr(rule.description) ?? `ScoutSuite: ${ruleId}`,
          resourceId,
          service,
          ...(cloudStr(rule.level) ? { severity: cloudStr(rule.level)! } : {}),
          ...(cloudStr(itemRec.region) ? { region: cloudStr(itemRec.region)! } : {}),
          evidence: `scoutsuite ${service}.${ruleId} flagged item`,
          ...(cloudStr(rule.description) ? { description: cloudStr(rule.description)! } : {}),
        }));
      }
    }
  }
  return out;
}

export function parseScoutSuiteText(text: string, ctx: CloudSecParserContext): NormalizedFinding[] {
  return parseScoutSuite(parseBoundedJson(text, { what: "scoutsuite report" }), ctx);
}

/** CloudMapper (§27): AWS account structure + network visualization
 *  data. The parser consumes its account JSON: nodes/edges become
 *  resource facts; public nodes are exposure evidence. */
export function parseCloudMapper(raw: unknown, ctx: CloudSecParserContext): { findings: NormalizedFinding[]; publicNodes: { id: string; type: string; region?: string }[] } {
  const root = cloudRec(raw);
  const findings: NormalizedFinding[] = [];
  const publicNodes: { id: string; type: string; region?: string }[] = [];
  const children = cloudArr(root.children);
  const walk = (nodes: Record<string, unknown>[]) => {
    for (const node of nodes) {
      const nodeType = cloudStr(node.node_type) ?? cloudStr(node.type) ?? "";
      const arn = cloudStr(node.arn) ?? cloudStr(node.id);
      if (arn && (node.public === true || node.public_access === true)) {
        publicNodes.push({ id: arn, type: nodeType, ...(cloudStr(node.region) ? { region: cloudStr(node.region)! } : {}) });
        findings.push(findingFromCheck(ctx, {
          checkId: "cloudmapper-public-node",
          title: `CloudMapper: internet-facing node ${cloudStr(node.name) ?? arn}`,
          resourceId: arn,
          service: nodeType,
          ...(cloudStr(node.region) ? { region: cloudStr(node.region)! } : {}),
          severity: "MEDIUM",
          evidence: "cloudmapper account graph marks the node public",
        }));
      }
      walk(cloudArr(node.children));
    }
  };
  walk(children.length > 0 ? children : cloudArr(root.nodes));
  return { findings, publicNodes };
}

export function parseCloudMapperText(text: string, ctx: CloudSecParserContext): ReturnType<typeof parseCloudMapper> {
  return parseCloudMapper(parseBoundedJson(text, { what: "cloudmapper report" }), ctx);
}

/** Steampipe (§32): governed query packs ONLY. Arbitrary SQL is never
 *  accepted from users or repositories — a query is identified by a
 *  pack id, and results are rows of check evidence. */
export const STEAMPIPE_QUERY_PACKS = [
  { id: "aws-cis-foundations", provider: "AWS" as const, description: "CIS AWS Foundations controls via Steampipe mod queries" },
  { id: "azure-cis-foundations", provider: "AZURE" as const, description: "CIS Azure Foundations controls via Steampipe mod queries" },
  { id: "gcp-cis-foundations", provider: "GCP" as const, description: "CIS GCP Foundations controls via Steampipe mod queries" },
  { id: "aws-public-exposure", provider: "AWS" as const, description: "Public exposure inventory queries" },
] as const;

export function evaluateSteampipeQuery(input: { packId?: string; sql?: string }): { allowed: boolean; reason?: string; packId?: string } {
  if (input.sql !== undefined && input.sql.trim().length > 0) {
    return { allowed: false, reason: "ARBITRARY_SQL_FORBIDDEN: Steampipe runs governed query packs only (§32)" };
  }
  const pack = STEAMPIPE_QUERY_PACKS.find((p) => p.id === input.packId);
  if (!pack) return { allowed: false, reason: "UNKNOWN_QUERY_PACK: only approved Steampipe packs may run (§32)" };
  return { allowed: true, packId: pack.id };
}

/** Steampipe connection config is a credential/endpoint surface:
 *  endpoints pass the SSRF guard (§101) and connection strings never
 *  carry embedded credentials. */
export function evaluateSteampipeConnection(input: { endpoint?: string }): { allowed: boolean; reason?: string } {
  if (!input.endpoint) return { allowed: true };
  const verdict = cloudEndpointVerdict(input.endpoint);
  return verdict.allowed ? { allowed: true } : { allowed: false, reason: verdict.reason };
}

export function parseSteampipeRows(raw: unknown, ctx: CloudSecParserContext): NormalizedFinding[] {
  const rows = Array.isArray(raw) ? cloudArr(raw as unknown) : cloudArr(cloudRec(raw).rows);
  const out: NormalizedFinding[] = [];
  for (const row of rows.slice(0, 5000)) {
    const status = (cloudStr(row.status) ?? "").toLowerCase();
    if (status !== "alarm" && status !== "fail") continue; // "ok" rows are PASS evidence (§23/§32)
    const resourceId = cloudStr(row.resource) ?? cloudStr(row.arn) ?? cloudStr(row.id);
    const checkId = cloudStr(row.control_id) ?? cloudStr(row.check_id) ?? cloudStr(row.reason) ?? "steampipe-check";
    if (!resourceId) continue;
    out.push(findingFromCheck(ctx, {
      checkId,
      title: cloudStr(row.title) ?? cloudStr(row.control_title) ?? `Steampipe: ${checkId}`,
      resourceId,
      ...(cloudStr(row.region) ? { region: cloudStr(row.region)! } : {}),
      ...(cloudStr(row.service) ? { service: cloudStr(row.service)! } : {}),
      ...(cloudStr(row.severity) ? { severity: cloudStr(row.severity)! } : {}),
      evidence: `steampipe row status=${status} reason=${sanitizeCloudText(cloudStr(row.reason) ?? "", 300)}`,
    }));
  }
  return out;
}

/** ROADtools (§29/§30): Azure AD / Entra ID DEFENSIVE analysis only —
 *  directory objects, role assignments, application permissions and
 *  risky relationships. Offensive graph operations (token theft,
 *  consent abuse, persistence) are never invoked or modeled as
 *  actions; imported data produces IAM_RISK findings only. */
export function parseRoadtools(raw: unknown, ctx: CloudSecParserContext): NormalizedFinding[] {
  const root = cloudRec(raw);
  const out: NormalizedFinding[] = [];
  const roadCtx: CloudSecParserContext = { ...ctx, provider: ctx.provider ?? "AZURE" };
  for (const assignment of cloudArr(root.role_assignments).slice(0, 2000)) {
    const role = (cloudStr(assignment.role) ?? cloudStr(assignment.role_name) ?? "").toLowerCase();
    const principal = cloudStr(assignment.principal) ?? cloudStr(assignment.principal_id);
    if (!principal) continue;
    if (role.includes("global administrator") || role.includes("company administrator") || role.includes("privileged role administrator")) {
      out.push(findingFromCheck(roadCtx, {
        checkId: "entra-privileged-role",
        title: `Entra privileged role assignment: ${principal}`,
        resourceId: principal,
        service: "iam",
        severity: "HIGH",
        evidence: `roadtools role assignment role=${cloudStr(assignment.role) ?? role} (defensive import, §29)`,
        description: `Directory principal ${principal} holds a privileged Entra role per ROADtools import. Defensive analysis only (§29): assignments are reviewed, never modified.`,
      }));
    }
  }
  for (const app of cloudArr(root.applications).slice(0, 2000)) {
    const perms = cloudArr(app.permissions).map((p) => cloudStr(p.name) ?? "").join(" ").toLowerCase();
    const appId = cloudStr(app.id) ?? cloudStr(app.app_id) ?? cloudStr(app.name);
    if (!appId) continue;
    if (perms.includes("role") && (perms.includes("write") || perms.includes("all"))) {
      out.push(findingFromCheck(roadCtx, {
        checkId: "entra-app-high-permissions",
        title: `Entra application with high-impact permissions: ${cloudStr(app.name) ?? appId}`,
        resourceId: appId,
        service: "iam",
        severity: "MEDIUM",
        evidence: "roadtools application permission import (defensive, §29)",
        description: "Application holds write-capable directory permissions per ROADtools import; review consent and necessity (§30).",
      }));
    }
  }
  return out;
}

export function parseRoadtoolsText(text: string, ctx: CloudSecParserContext): NormalizedFinding[] {
  return parseRoadtools(parseBoundedJson(text, { what: "roadtools export" }), ctx);
}
