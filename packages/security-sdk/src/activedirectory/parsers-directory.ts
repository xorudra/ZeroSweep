/**
 * Prompt 15 — directory tool output parsers (§16/§28/§31/§39/§41/§44/§48).
 *
 * Every parser treats its input as HOSTILE (§16/§115): bounded sizes,
 * depth caps, sanitized strings, credential material stripped. Parsers
 * only ever produce NORMALIZED INVENTORY + FINDINGS — a parser can
 * never produce an executable action, a credential, or a downloaded
 * file (§44: SMBMap content is never fetched; §48: Certipy findings
 * are posture metadata).
 */
import type { NormalizedFinding } from "../findings/finding.types";
import type {
  NormalizedCertificateAuthority, NormalizedCertificateTemplate, NormalizedDirectoryData,
  NormalizedDirectoryGpo, NormalizedDirectoryGroup, NormalizedDirectoryOU,
  NormalizedDirectoryRelationship, NormalizedDirectoryTrust, NormalizedDirectoryUser,
  NormalizedDirectoryComputer, NormalizedDomainController, NormalizedSmbShare,
} from "./types";
import { classifyGroupPrivilege } from "./types";
import { dirArr, dirBool, dirNum, dirRec, dirStr, dirStrList, parseBoundedDirectoryJson, sanitizeDirectoryText, stripCredentialMaterial } from "./guards";
import { parseXmlLite, firstChild, type XmlNode } from "../network/xml-lite";
import { directoryFingerprint } from "./correlation";

export interface DirectoryParseContext {
  domainDnsName: string;
  domainId?: string;
  source: string; // adapter slug recorded as edge provenance (§33)
  /** Session/local-access edges are sensitive (§69): parsed only when
   *  the collection policy approved them (§29 REVIEW_REQUIRED set). */
  includeSessions?: boolean;
  includeLocalAdmins?: boolean;
  now?: Date;
}

function emptyDirectory(): NormalizedDirectoryData {
  return {
    domainControllers: [], users: [], groups: [], computers: [], organizationalUnits: [],
    groupPolicies: [], trusts: [], relationships: [], smbShares: [],
    certificateAuthorities: [], certificateTemplates: [],
  };
}

function tsToIso(v: unknown): string | undefined {
  const n = dirNum(v);
  if (n === undefined || n <= 0) return undefined;
  const ms = n > 1e12 ? n : n * 1000;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function delegationOf(props: Record<string, unknown>): { type: "NONE" | "UNCONSTRAINED" | "CONSTRAINED" | "RESOURCE_BASED"; targets: string[] } {
  if (dirBool(props.unconstraineddelegation) === true || dirBool(props.unconstrainedDelegation) === true) {
    return { type: "UNCONSTRAINED", targets: [] };
  }
  const targets = dirStrList(props.allowedtodelegate ?? props.allowedToDelegate ?? props.delegationTargets);
  if (targets.length > 0) return { type: "CONSTRAINED", targets };
  if (dirBool(props.resourcebasedconstraineddelegation) === true) return { type: "RESOURCE_BASED", targets: [] };
  return { type: "NONE", targets: [] };
}

const ACE_RIGHT_MAP: Record<string, string> = {
  GenericAll: "GENERIC_ALL", GenericWrite: "GENERIC_WRITE", WriteDacl: "WRITE_DACL",
  WriteOwner: "WRITE_OWNER", Owns: "OWNS",
};

function principalType(t: string | undefined): string {
  switch ((t ?? "").toLowerCase()) {
    case "user": return "USER";
    case "group": return "GROUP";
    case "computer": return "COMPUTER";
    case "gpo": return "GPO";
    case "ou": return "OU";
    case "domain": return "DOMAIN";
    default: return (t ?? "USER").toUpperCase();
  }
}

function aceEdges(raw: Record<string, unknown>, targetType: string, targetRef: string, ctx: DirectoryParseContext): NormalizedDirectoryRelationship[] {
  const out: NormalizedDirectoryRelationship[] = [];
  for (const ace of dirArr(raw.Aces ?? raw.aces)) {
    const right = dirStr(ace.RightName ?? ace.rightName);
    const principal = dirStr(ace.PrincipalSID ?? ace.PrincipalId ?? ace.principalSid);
    if (!right || !principal) continue;
    const relationship = ACE_RIGHT_MAP[right];
    if (!relationship) continue; // read-only rights (GenericRead etc.) are not privilege edges
    out.push({
      fromType: principalType(dirStr(ace.PrincipalType ?? ace.principalType)),
      fromRef: principal, toType: targetType, toRef: targetRef,
      relationship, source: ctx.source, confidence: "HIGH",
      evidenceRef: `ace:${right}`,
    });
  }
  return out;
}

function nameBeforeAt(name: string | undefined): string | undefined {
  if (!name) return undefined;
  const at = name.indexOf("@");
  return at > 0 ? name.slice(0, at) : name;
}

// ── BloodHound / SharpHound export import (§28/§31) ──────────────────

export interface BloodHoundParseResult {
  directory: NormalizedDirectoryData;
  counts: Record<string, number>;
  sessionsDropped: number;
}

/**
 * Normalize a BloodHound/SharpHound JSON export into directory
 * inventory + evidence-backed relationships. Accepts the aggregated
 * export shape ({ users: [], groups: [], computers: [], domains: [],
 * ous: [], gpos: [] }) and single-type exports ({ data: [], meta:
 * { type } }). Object names are hostile text (§115) — everything is
 * sanitized, and credential-material-shaped attributes are stripped
 * (§19/§113). Session edges are dropped unless the collection policy
 * approved them (§29/§69) — the drop is counted, never silent.
 */
export function parseBloodHoundExport(input: unknown, ctx: DirectoryParseContext): BloodHoundParseResult {
  const root = dirRec(input);
  const sections: Record<string, Record<string, unknown>[]> = {};
  for (const key of ["users", "groups", "computers", "domains", "ous", "gpos", "containers"]) {
    if (Array.isArray(root[key])) sections[key] = dirArr(root[key]);
  }
  if (Array.isArray(root.data)) {
    const type = dirStr(dirRec(root.meta).type)?.toLowerCase();
    if (type) sections[type] = dirArr(root.data);
  }
  const directory = emptyDirectory();
  let sessionsDropped = 0;
  const relationships: NormalizedDirectoryRelationship[] = directory.relationships;

  // Groups first — DC detection keys off Domain Controllers membership.
  const dcComputerNames = new Set<string>();
  for (const g of sections.groups ?? []) {
    const props = stripCredentialMaterial(dirRec(g.Properties ?? g.properties));
    const objectId = dirStr(g.ObjectIdentifier ?? g.objectId) ?? "";
    if (!objectId) continue;
    const name = nameBeforeAt(dirStr(props.name)) ?? objectId;
    const group: NormalizedDirectoryGroup = {
      objectId, name,
      privilegeClass: classifyGroupPrivilege({ objectId }),
      ...(dirNum(dirRec(g.Meta ?? g.meta).count) !== undefined ? { memberCount: dirNum(dirRec(g.Meta ?? g.meta).count) } : {}),
    };
    directory.groups.push(group);
    for (const m of dirArr(g.Members ?? g.members)) {
      const memberId = dirStr(m.ObjectIdentifier ?? m.objectId);
      if (!memberId) continue;
      const mType = principalType(dirStr(m.ObjectType ?? m.objectType));
      relationships.push({
        fromType: mType, fromRef: memberId, toType: "GROUP", toRef: objectId,
        relationship: "MEMBER_OF", source: ctx.source, confidence: "HIGH",
      });
      if (/domain controllers/i.test(name) && mType === "COMPUTER") dcComputerNames.add(memberId);
    }
    relationships.push(...aceEdges(g, "GROUP", objectId, ctx));
  }

  for (const u of sections.users ?? []) {
    const props = stripCredentialMaterial(dirRec(u.Properties ?? u.properties));
    const objectId = dirStr(u.ObjectIdentifier ?? u.objectId) ?? "";
    if (!objectId) continue;
    const spns = dirStrList(props.serviceprincipalnames ?? props.spns);
    const delegation = delegationOf(props);
    const user: NormalizedDirectoryUser = {
      objectId,
      samAccountName: dirStr(props.samaccountname) ?? nameBeforeAt(dirStr(props.name)) ?? objectId,
      enabled: dirBool(props.enabled) ?? true,
      ...(dirStr(props.displayname) ? { displayName: dirStr(props.displayname) } : {}),
      ...(dirStr(props.userprincipalname) ?? dirStr(props.name) ? { userPrincipalName: dirStr(props.userprincipalname) ?? dirStr(props.name) } : {}),
      isServiceAccount: spns.length > 0 || dirBool(props.isserviceaccount) === true,
      passwordNeverExpires: dirBool(props.pwdneverexpires) ?? false,
      passwordNotRequired: dirBool(props.passwordnotrequired) ?? false,
      preauthNotRequired: dirBool(props.dontreqpreauth) ?? false,
      spnPresent: spns.length > 0,
      spns,
      delegationType: delegation.type,
      delegationTargets: delegation.targets,
      ...(tsToIso(props.lastlogontimestamp ?? props.lastlogon) ? { lastLogonAt: tsToIso(props.lastlogontimestamp ?? props.lastlogon) } : {}),
      ...(tsToIso(props.passwordlastset ?? props.pwdlastset) ? { passwordLastSetAt: tsToIso(props.passwordlastset ?? props.pwdlastset) } : {}),
    };
    directory.users.push(user);
    relationships.push(...aceEdges(u, user.isServiceAccount ? "SERVICE_ACCOUNT" : "USER", objectId, ctx));
  }

  for (const c of sections.computers ?? []) {
    const props = stripCredentialMaterial(dirRec(c.Properties ?? c.properties));
    const objectId = dirStr(c.ObjectIdentifier ?? c.objectId) ?? "";
    if (!objectId) continue;
    const fqdn = dirStr(props.name) ?? objectId;
    const delegation = delegationOf(props);
    const isDc = dirBool(props.isdc) === true || dcComputerNames.has(objectId);
    const computer: NormalizedDirectoryComputer = {
      objectId, hostname: fqdn.includes(".") ? fqdn.split(".")[0]! : fqdn, dnsName: fqdn,
      enabled: dirBool(props.enabled) ?? true,
      ...(dirStr(props.operatingsystem) ? { osName: dirStr(props.operatingsystem) } : {}),
      isDomainController: isDc,
      delegationType: delegation.type,
      delegationTargets: delegation.targets,
    };
    directory.computers.push(computer);
    if (isDc) {
      const services = dirRec(props.services);
      directory.domainControllers.push({
        hostname: computer.hostname, dnsName: fqdn, ipAddresses: dirStrList(props.ipaddresses ?? props.ipAddresses),
        ...(computer.osName ? { osName: computer.osName } : {}), objectId, services,
      } satisfies NormalizedDomainController);
    }
    if (ctx.includeLocalAdmins) {
      for (const la of dirArr(dirRec(c.LocalAdmins ?? c.localAdmins).Results ?? dirRec(c.LocalAdmins ?? c.localAdmins).results)) {
        const pid = dirStr(la.ObjectIdentifier ?? la.objectId);
        if (!pid) continue;
        relationships.push({
          fromType: principalType(dirStr(la.ObjectType ?? la.objectType)), fromRef: pid,
          toType: "COMPUTER", toRef: objectId, relationship: "ADMIN_TO",
          source: ctx.source, confidence: "HIGH",
        });
      }
      for (const la of dirArr(dirRec(c.RemoteDesktopUsers ?? c.remoteDesktopUsers).Results)) {
        const pid = dirStr(la.ObjectIdentifier ?? la.objectId);
        if (!pid) continue;
        relationships.push({
          fromType: principalType(dirStr(la.ObjectType ?? la.objectType)), fromRef: pid,
          toType: "COMPUTER", toRef: objectId, relationship: "CAN_RDP",
          source: ctx.source, confidence: "MEDIUM",
        });
      }
    }
    const sessions = dirArr(dirRec(c.Sessions ?? c.sessions).Results ?? dirRec(c.Sessions ?? c.sessions).results);
    if (sessions.length > 0) {
      if (ctx.includeSessions) {
        for (const s of sessions) {
          const uid = dirStr(s.UserId ?? s.userId);
          if (!uid) continue;
          relationships.push({
            fromType: "USER", fromRef: uid, toType: "COMPUTER", toRef: objectId,
            relationship: "HAS_SESSION", source: ctx.source, confidence: "MEDIUM",
            evidenceRef: "sharphound-session",
          });
        }
      } else {
        sessionsDropped += sessions.length; // §69: minimized by default; the drop is reported
      }
    }
    relationships.push(...aceEdges(c, "COMPUTER", objectId, ctx));
  }

  for (const d of sections.domains ?? []) {
    const props = stripCredentialMaterial(dirRec(d.Properties ?? d.properties));
    const sid = dirStr(d.ObjectIdentifier ?? d.objectId);
    directory.domain = {
      dnsName: ctx.domainDnsName,
      ...(dirStr(props.name) ? { netbiosName: nameBeforeAt(dirStr(props.name)) } : {}),
      ...(sid ? { domainSid: sid } : {}),
      ...(dirStr(props.functionallevel) ? { functionalLevel: dirStr(props.functionallevel) } : {}),
    };
    const policy = dirRec(props.passwordpolicy ?? props.passwordPolicy);
    if (Object.keys(policy).length > 0) directory.passwordPolicy = policy;
    for (const t of dirArr(d.Trusts ?? d.trusts)) {
      const target = dirStr(t.TargetDomainName ?? t.targetDomainName);
      if (!target) continue;
      const dirNum2 = dirNum(t.TrustDirection ?? t.trustDirection);
      const direction: NormalizedDirectoryTrust["direction"] = dirNum2 === 1 ? "INBOUND" : dirNum2 === 2 ? "OUTBOUND" : dirNum2 === 3 ? "BIDIRECTIONAL" : "BIDIRECTIONAL";
      const trustTypeRaw = dirNum(t.TrustType ?? t.trustType);
      const trustType: NormalizedDirectoryTrust["trustType"] = trustTypeRaw === 0 ? "PARENT_CHILD" : trustTypeRaw === 2 ? "FOREST" : trustTypeRaw === 1 || trustTypeRaw === 3 ? "EXTERNAL" : "UNKNOWN";
      directory.trusts.push({
        targetDomainName: target,
        ...(dirStr(t.TargetDomainSid ?? t.targetDomainSid) ? { targetDomainSid: dirStr(t.TargetDomainSid ?? t.targetDomainSid) } : {}),
        direction, trustType,
        transitive: dirBool(t.IsTransitive ?? t.isTransitive) ?? true,
        ...(dirBool(t.SidFilteringEnabled ?? t.sidFilteringEnabled) !== undefined ? { sidFilteringEnabled: dirBool(t.SidFilteringEnabled ?? t.sidFilteringEnabled) } : {}),
        ...(dirBool(t.SelectiveAuthentication ?? t.selectiveAuthentication) !== undefined ? { selectiveAuthentication: dirBool(t.SelectiveAuthentication ?? t.selectiveAuthentication) } : {}),
      });
      relationships.push({
        fromType: "DOMAIN", fromRef: ctx.domainDnsName, toType: "DOMAIN", toRef: target,
        relationship: "TRUST", source: ctx.source, confidence: "HIGH",
      });
    }
    if (sid) relationships.push(...aceEdges(d, "DOMAIN", sid, ctx));
  }

  for (const o of sections.ous ?? []) {
    const props = stripCredentialMaterial(dirRec(o.Properties ?? o.properties));
    const objectId = dirStr(o.ObjectIdentifier ?? o.objectId) ?? "";
    if (!objectId) continue;
    const links = dirArr(o.Links ?? o.links).map((l) => dirStr(l.GUID ?? l.guid ?? l.ObjectIdentifier)).filter((x): x is string => !!x);
    directory.organizationalUnits.push({
      objectId, name: dirStr(props.name) ?? objectId,
      distinguishedName: dirStr(props.distinguishedname) ?? "",
      linkedGpoIds: links,
    });
    for (const gpoId of links) {
      relationships.push({
        fromType: "OU", fromRef: objectId, toType: "GPO", toRef: gpoId,
        relationship: "GPO_LINK", source: ctx.source, confidence: "HIGH",
      });
    }
  }

  for (const g of sections.gpos ?? []) {
    const props = stripCredentialMaterial(dirRec(g.Properties ?? g.properties));
    const objectId = dirStr(g.ObjectIdentifier ?? g.objectId) ?? "";
    if (!objectId) continue;
    directory.groupPolicies.push({
      objectId, name: dirStr(props.displayname) ?? dirStr(props.name) ?? objectId,
      linkedTo: [], securityMetadata: dirRec(props.securitymetadata), delegationMetadata: {},
    });
  }

  const counts: Record<string, number> = {
    users: directory.users.length, groups: directory.groups.length, computers: directory.computers.length,
    domainControllers: directory.domainControllers.length, organizationalUnits: directory.organizationalUnits.length,
    groupPolicies: directory.groupPolicies.length, trusts: directory.trusts.length,
    relationships: relationships.length,
  };
  return { directory, counts, sessionsDropped };
}

// ── PingCastle report import (§38/§39) ───────────────────────────────

export interface PingCastleRule {
  model: string;
  category: string;
  title: string;
  points: number;
  description: string;
  technicalExplanation: string;
  remediation: string;
  /** Governed canonical mapping (§109): when a PingCastle rule matches
   *  a native analyzer rule, findings from both share a fingerprint so
   *  the same issue converges on ONE canonical finding. */
  canonicalRuleId?: string;
}

export interface PingCastleParseResult {
  domainName?: string;
  /** The PingCastle global score, preserved SEPARATELY from the
   *  ZeroSweep risk score (§39) — products never overwrite each other. */
  pingcastleScore?: number;
  rules: PingCastleRule[];
  findings: NormalizedFinding[];
}

/** Governed PingCastle-model → native-rule mapping (title/model keyword
 *  based, deliberately conservative: only well-understood checks map). */
const PINGCASTLE_CANONICAL_MAP: { match: RegExp; ruleId: string }[] = [
  { match: /krbtgt/i, ruleId: "AD_KRBTGT_OLD" },
  { match: /preauth|as-?rep/i, ruleId: "AD_PREAUTH_NOT_REQUIRED" },
  { match: /unconstrained|delegation/i, ruleId: "AD_UNCONSTRAINED_DELEGATION" },
  { match: /stale|inactive.*account|unused.*account/i, ruleId: "AD_STALE_ENABLED_ACCOUNT" },
  { match: /smb.*v1|smbv1/i, ruleId: "AD_SMB1_ENABLED" },
  { match: /ldap.*sign|signing/i, ruleId: "AD_LDAP_SIGNING_NOT_REQUIRED" },
  { match: /privileged|domain admin/i, ruleId: "AD_PRIVILEGED_GROUP_EXCESS" },
  { match: /password.*policy|pwd.*complex/i, ruleId: "AD_PASSWORD_POLICY_WEAK" },
  { match: /trust/i, ruleId: "AD_TRUST_REVIEW" },
  { match: /anonymous/i, ruleId: "AD_SMB_ANONYMOUS_SHARE" },
];

function pingcastleSeverity(points: number): NormalizedFinding["severity"] {
  if (points >= 30) return "CRITICAL";
  if (points >= 15) return "HIGH";
  if (points >= 5) return "MEDIUM";
  if (points > 0) return "LOW";
  return "INFORMATIONAL";
}

function xmlText(node: XmlNode | undefined): string {
  return node ? sanitizeDirectoryText(node.text, 4000) : "";
}

/** xml-lite lowercases tag names — all lookups go through here. */
function xmlChild(node: XmlNode, ...tags: string[]): XmlNode | undefined {
  for (const tag of tags) {
    const found = firstChild(node, tag.toLowerCase());
    if (found) return found;
  }
  return undefined;
}

/**
 * Parse a PingCastle XML report (§38): rule identity, category,
 * severity (from points), evidence, affected-object text and
 * remediation are extracted per rule; the global score is preserved
 * separately (§39). The XML reader rejects DTD/ENTITY constructs —
 * XXE is structurally impossible. Titles/descriptions are sanitized
 * hostile text (§115).
 */
export function parsePingCastleReport(xml: string, ctx: DirectoryParseContext): PingCastleParseResult {
  const parsed = parseXmlLite(xml);
  if ("error" in parsed) throw new Error(`pingcastle report: ${parsed.error}`);
  // Walk the whole tree collecting healthcheck sections + rules.
  const rules: PingCastleRule[] = [];
  let domainName: string | undefined;
  let pingcastleScore: number | undefined;
  const stack: XmlNode[] = [parsed.root];
  const ruleNodes: XmlNode[] = [];
  while (stack.length > 0) {
    const node = stack.pop()!;
    const tag = node.tag.toLowerCase();
    if (tag.includes("healthcheckdata") || tag === "pingcastledata") {
      domainName = node.attrs.domainname ?? xmlText(xmlChild(node, "DomainFQDN")) ?? domainName;
      const scoreAttr = node.attrs.globalscore ?? node.attrs.score;
      if (scoreAttr && Number.isFinite(Number(scoreAttr))) pingcastleScore = Number(scoreAttr);
      const scoreNode = xmlChild(node, "GlobalScore", "Score");
      if (scoreNode && Number.isFinite(Number(scoreNode.text))) pingcastleScore = Number(scoreNode.text);
    }
    if (tag.includes("riskrule") || tag.includes("healthcheckrule") || (tag === "rule" && xmlChild(node, "Title"))) {
      ruleNodes.push(node);
    }
    for (const child of node.children) stack.push(child);
  }
  for (const rn of ruleNodes) {
    const pointsRaw = xmlText(xmlChild(rn, "Points", "Score")) || rn.attrs.points || "0";
    const points = Number.isFinite(Number(pointsRaw)) ? Number(pointsRaw) : 0;
    const model = xmlText(xmlChild(rn, "Model", "Id")) || rn.attrs.model || rn.attrs.id || "";
    const title = xmlText(xmlChild(rn, "Title")) || model;
    if (!title) continue;
    const canonical = PINGCASTLE_CANONICAL_MAP.find((m) => m.match.test(`${model} ${title}`));
    rules.push({
      model: sanitizeDirectoryText(model, 200) || title,
      category: xmlText(xmlChild(rn, "Category")) || "Uncategorized",
      title,
      points,
      description: xmlText(xmlChild(rn, "Description", "Details")),
      technicalExplanation: xmlText(xmlChild(rn, "TechnicalExplanation", "Rationale")),
      remediation: xmlText(xmlChild(rn, "Recommendation", "Remediation")),
      ...(canonical ? { canonicalRuleId: canonical.ruleId } : {}),
    });
  }
  const findings: NormalizedFinding[] = rules.filter((r) => r.points > 0).map((rule) => {
    const ruleId = rule.canonicalRuleId ?? `pingcastle:${rule.model}`;
    return {
      title: sanitizeDirectoryText(`PingCastle: ${rule.title}`, 300),
      description: sanitizeDirectoryText(rule.description || rule.technicalExplanation || rule.title, 2000),
      severity: pingcastleSeverity(rule.points),
      confidence: 0.8,
      references: [],
      sourceTool: "pingcastle",
      sourceFingerprint: directoryFingerprint({
        domainRef: ctx.domainDnsName, ruleId,
        ...(rule.canonicalRuleId ? {} : { objectId: rule.model }),
      }),
      ruleId,
      directoryDomainRef: ctx.domainDnsName,
      ...(ctx.domainId ? { directoryDomainId: ctx.domainId } : {}),
      evidence: sanitizeDirectoryText(
        `PingCastle rule ${rule.model} (category: ${rule.category}) scored ${rule.points} points. ` +
        `PingCastle score is preserved separately from the ZeroSweep risk score (§39). ${rule.technicalExplanation}`.trim(), 1000),
      ...(rule.remediation ? { remediation: sanitizeDirectoryText(rule.remediation, 1000) } : {}),
    } satisfies NormalizedFinding;
  });
  return { ...(domainName ? { domainName } : {}), ...(pingcastleScore !== undefined ? { pingcastleScore } : {}), rules, findings };
}

// ── Certipy find (posture) JSON (§48) ────────────────────────────────

export interface CertipyParseResult {
  certificateAuthorities: NormalizedCertificateAuthority[];
  certificateTemplates: NormalizedCertificateTemplate[];
}

/**
 * Normalize a Certipy `find` JSON export (§48/§49). This is the
 * POSTURE surface only: CA + template configuration metadata. Certipy
 * output fields that carry request/auth material are never read.
 */
export function parseCertipyFind(input: unknown, _ctx: DirectoryParseContext): CertipyParseResult {
  const root = dirRec(input);
  const cas: NormalizedCertificateAuthority[] = [];
  const templates: NormalizedCertificateTemplate[] = [];
  const caSection = dirRec(root["Certificate Authorities"] ?? root.certificateAuthorities ?? root.cas);
  for (const ca of Object.values(caSection).length > 0 ? Object.values(caSection).map((v) => dirRec(v)) : dirArr(root.certificateAuthorities)) {
    const name = dirStr(ca["CA Name"] ?? ca.name);
    if (!name) continue;
    const metadata = stripCredentialMaterial({
      ...(dirBool(ca["Enforce Encryption for Requests"] ?? ca.enforceEncryption) !== undefined ? { enforceEncryptionForRequests: dirBool(ca["Enforce Encryption for Requests"] ?? ca.enforceEncryption) } : {}),
      ...(dirStr(ca["User Specified SAN"] ?? ca.userSpecifiedSan) ? { userSpecifiedSan: dirStr(ca["User Specified SAN"] ?? ca.userSpecifiedSan) } : {}),
      editFlags: dirStr(ca["Edit Flags"] ?? ca.editFlags) ?? "",
      webEnrollment: dirStr(ca["Web Enrollment"] ?? ca.webEnrollment) ?? "",
    });
    cas.push({
      name,
      ...(dirStr(ca["DNS Name"] ?? ca.dnsName) ? { dnsName: dirStr(ca["DNS Name"] ?? ca.dnsName) } : {}),
      enrollmentServices: dirStrList(ca.enrollmentServices ?? ca["Enrollment Services"]),
      metadata,
    });
  }
  const tplSection = dirRec(root["Certificate Templates"] ?? root.certificateTemplates ?? root.templates);
  const tplList: Record<string, unknown>[] = Object.keys(tplSection).length > 0
    ? Object.entries(tplSection).map(([key, v]) => ({ ...dirRec(v), _key: key }))
    : dirArr(root.certificateTemplates);
  for (const t of tplList) {
    // Certipy keys the section by index — the name lives in the record;
    // the key is only a fallback for exporters that key by name.
    const name = dirStr(t["Template Name"] ?? t.name) ?? (typeof t._key === "string" && !/^\d+$/.test(t._key) ? t._key : undefined);
    if (!name) continue;
    templates.push({
      name,
      ...(dirStr(t.caName) ? { caName: dirStr(t.caName) } : {}),
      enabled: dirBool(t.Enabled ?? t.enabled) ?? true,
      enrollmentPermissions: dirRec(t["Enrollment Permissions"] ?? t.enrollmentPermissions),
      subjectConfig: {
        enrolleeSuppliesSubject: dirBool(t["Enrollee Supplies Subject"] ?? dirRec(t.subjectConfig ?? {}).enrolleeSuppliesSubject) ?? false,
      },
      authenticationEkus: dirStrList(t["Extended Key Usage"] ?? t.authenticationEkus ?? t.ekus),
      managerApprovalRequired: dirBool(t["Manager Approval Required"] ?? t.managerApprovalRequired) ?? false,
      authorizedSignaturesRequired: dirNum(t["Authorized Signatures Required"] ?? t.authorizedSignaturesRequired) ?? 0,
      issuanceRequirements: dirRec(t["Issuance Requirements"] ?? t.issuanceRequirements),
      riskClasses: [],
    });
  }
  return { certificateAuthorities: cas, certificateTemplates: templates };
}

// ── SmbMap / enum4linux-ng share + service output (§41/§44) ─────────

export interface SmbParseResult {
  shares: NormalizedSmbShare[];
  services: { host: string; port: number; service: string; detail: string }[];
}

/** Normalize SmbMap JSON: share names + permission strings ONLY. The
 *  record shape has no field for file listings or contents — SmbMap
 *  recursive-listing/download output is dropped by construction (§44). */
export function parseSmbMapOutput(input: unknown, ctx: DirectoryParseContext): SmbParseResult {
  const root = dirRec(input);
  const shares: NormalizedSmbShare[] = [];
  const hosts = dirArr(root.hosts ?? root.results ?? (Array.isArray(input) ? input : []));
  for (const h of hosts) {
    const host = dirStr(h.host ?? h.ip ?? h.hostname) ?? "";
    if (!host) continue;
    for (const s of dirArr(h.shares)) {
      const shareName = dirStr(s.name ?? s.share_name);
      if (!shareName) continue;
      const perms = (dirStr(s.permissions ?? s.access) ?? "").toUpperCase();
      const accessLevel: NormalizedSmbShare["accessLevel"] = perms.includes("READ, WRITE") || perms.includes("READ_WRITE") || perms === "RW"
        ? "READ_WRITE" : perms.includes("READ") ? "READ" : perms.includes("NO ACCESS") || perms.includes("NONE") ? "NONE" : "UNKNOWN";
      shares.push({
        host, shareName, accessLevel,
        ...(dirBool(s.anonymous) !== undefined ? { anonymousAccess: dirBool(s.anonymous) } : {}),
        source: ctx.source,
      });
    }
  }
  return { shares, services: [] };
}

/** Normalize enum4linux-ng JSON: SMB dialect/signing posture + shares.
 *  Only authorized hosts are ever queried by the adapter (§41); the
 *  parser records protocol metadata — no credential guessing exists
 *  anywhere in the flow (§120). */
export function parseEnum4linuxNgOutput(input: unknown, ctx: DirectoryParseContext): SmbParseResult {
  const root = dirRec(input);
  const shares: NormalizedSmbShare[] = [];
  const services: SmbParseResult["services"] = [];
  const target = dirStr(root.target ?? root.host) ?? "";
  const smb = dirRec(root.smb ?? root.SMB);
  const dialect = dirStr(smb.dialect ?? smb.protocol);
  const signing = dirBool(smb.signing_required ?? smb.signingRequired);
  if (target && dialect) {
    services.push({ host: target, port: 445, service: "microsoft-ds", detail: `SMB dialect ${dialect}${signing !== undefined ? `, signing ${signing ? "required" : "not required"}` : ""}` });
  }
  for (const s of dirArr(root.shares)) {
    const shareName = dirStr(s.name ?? s.share_name);
    if (!shareName || !target) continue;
    shares.push({
      host: target, shareName,
      accessLevel: "UNKNOWN",
      ...(dialect ? { smbDialect: dialect } : {}),
      ...(signing !== undefined ? { signingRequired: signing } : {}),
      source: ctx.source,
    });
  }
  return { shares, services };
}

// ── LDAP directory entries (§13–§17) ────────────────────────────────

/**
 * Normalize raw LDAP search entries (as the connector returns them)
 * into directory inventory. Attribute values are sanitized and
 * credential-material-shaped values are stripped (§16/§19). Entries
 * beyond the budget count are truncated by the CALLER via the budget;
 * this function is pure normalization.
 */
export function parseLdapEntries(entries: unknown, ctx: DirectoryParseContext): NormalizedDirectoryData {
  const directory = emptyDirectory();
  for (const raw of dirArr(entries)) {
    const e = stripCredentialMaterial(raw);
    const objectClass = dirStrList(e.objectClass ?? e.objectclass).map((s) => s.toLowerCase());
    const objectId = dirStr(e.objectSid ?? e.objectGUID ?? e.objectId ?? e.dn) ?? "";
    if (!objectId) continue;
    if (objectClass.includes("user") || objectClass.includes("person")) {
      const spns = dirStrList(e.servicePrincipalName);
      const uac = dirNum(e.userAccountControl) ?? 0;
      directory.users.push({
        objectId,
        samAccountName: dirStr(e.sAMAccountName) ?? objectId,
        ...(dirStr(e.displayName) ? { displayName: dirStr(e.displayName) } : {}),
        ...(dirStr(e.userPrincipalName) ? { userPrincipalName: dirStr(e.userPrincipalName) } : {}),
        enabled: (uac & 0x2) === 0,
        isServiceAccount: spns.length > 0,
        passwordNeverExpires: (uac & 0x10000) !== 0,
        passwordNotRequired: (uac & 0x20) !== 0,
        preauthNotRequired: (uac & 0x400000) !== 0,
        spnPresent: spns.length > 0,
        spns,
        delegationType: dirStr(e.msDS_AllowedToDelegateTo) || (Array.isArray(e.msDS_AllowedToDelegateTo) && e.msDS_AllowedToDelegateTo.length > 0) ? "CONSTRAINED" : "NONE",
        delegationTargets: dirStrList(e.msDS_AllowedToDelegateTo),
        ...(dirStr(e.lastLogon) ? { lastLogonAt: dirStr(e.lastLogon) } : {}),
        ...(dirStr(e.pwdLastSet) ? { passwordLastSetAt: dirStr(e.pwdLastSet) } : {}),
      });
    } else if (objectClass.includes("group")) {
      directory.groups.push({
        objectId,
        name: dirStr(e.name) ?? dirStr(e.sAMAccountName) ?? objectId,
        privilegeClass: classifyGroupPrivilege({ objectId }),
      });
      for (const memberDn of dirStrList(e.member)) {
        directory.relationships.push({
          fromType: "USER", fromRef: memberDn, toType: "GROUP", toRef: objectId,
          relationship: "MEMBER_OF", source: ctx.source, confidence: "MEDIUM",
          evidenceRef: "ldap:member",
        });
      }
    } else if (objectClass.includes("computer")) {
      const fqdn = dirStr(e.dNSHostName) ?? dirStr(e.name) ?? objectId;
      directory.computers.push({
        objectId, hostname: nameBeforeAt(fqdn) ?? fqdn, dnsName: fqdn,
        enabled: true,
        ...(dirStr(e.operatingSystem) ? { osName: dirStr(e.operatingSystem) } : {}),
      });
    } else if (objectClass.includes("organizationalunit")) {
      directory.organizationalUnits.push({
        objectId, name: dirStr(e.name) ?? objectId,
        distinguishedName: dirStr(e.dn) ?? dirStr(e.distinguishedName) ?? "",
        linkedGpoIds: dirStrList(e.gPLink).length > 0 ? dirStrList(e.gPLink) : [],
      });
    } else if (objectClass.includes("trusteddomain")) {
      const target = dirStr(e.trustPartner ?? e.name);
      if (target) {
        directory.trusts.push({
          targetDomainName: target, direction: "BIDIRECTIONAL", trustType: "UNKNOWN", transitive: true,
        });
      }
    }
  }
  return directory;
}

/** Parse any supported directory payload format by content. Used by
 *  the manual-import path; throws a descriptive error for unknown
 *  shapes — an import NEVER guesses silently. */
export function parseDirectoryPayload(text: string, format: string, ctx: DirectoryParseContext): NormalizedDirectoryData & { findings: NormalizedFinding[] } {
  switch (format) {
    case "bloodhound-json": {
      const json = parseBoundedDirectoryJson(text, { what: "BloodHound export" });
      const { directory } = parseBloodHoundExport(json, ctx);
      return { ...directory, findings: [] };
    }
    case "pingcastle-xml": {
      const result = parsePingCastleReport(text, ctx);
      const directory = emptyDirectory();
      if (result.domainName) directory.domain = { dnsName: result.domainName };
      return { ...directory, findings: result.findings };
    }
    case "certipy-json": {
      const json = parseBoundedDirectoryJson(text, { what: "Certipy output" });
      const parsed = parseCertipyFind(json, ctx);
      const directory = emptyDirectory();
      directory.certificateAuthorities = parsed.certificateAuthorities;
      directory.certificateTemplates = parsed.certificateTemplates;
      return { ...directory, findings: [] };
    }
    case "ldap-json": {
      const json = parseBoundedDirectoryJson(text, { what: "LDAP entries" });
      const directory = parseLdapEntries(Array.isArray(json) ? json : dirRec(json).entries, ctx);
      return { ...directory, findings: [] };
    }
    default:
      throw new Error(`unsupported directory import format: ${format}`);
  }
}
