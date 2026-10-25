/**
 * Prompt 15 — directory posture analysis (§57–§78/§81).
 *
 * Deterministic analyzers over NORMALIZED collected data — the same
 * platform-stage pattern as P13/P14: no network, no tool execution,
 * no inference beyond the evidence. Every finding carries the rule id,
 * the affected directory object and sanitized evidence; the identity
 * and computer risk scores are explainable factor sums (§77/§78), and
 * the ZeroSweep severity is independent of any tool's own score (§39).
 */
import type { NormalizedFinding } from "../findings/finding.types";
import type { NormalizedControlAssessment } from "../findings/finding.types";
import type {
  DirectoryBudget, NormalizedCertificateTemplate, NormalizedDirectoryData,
  NormalizedDirectoryGroup, NormalizedDirectoryUser, StaleAccountPolicy,
} from "./types";
import { ADCS_RISK_CLASSES, DEFAULT_STALE_ACCOUNT_POLICY, clampDirectoryBudget, clampStaleAccountPolicy, isPrivilegedGroup } from "./types";
import { sanitizeDirectoryText } from "./guards";
import { directoryFingerprint, directoryRemediation } from "./correlation";
import { buildIdentityGraph, privilegedPrincipals, resolveNestedGroups } from "./graph";

export interface DirectoryAnalysisContext {
  domainId?: string;
  domainRef: string; // DNS name — fingerprint component
  toolSlug: string;
  now?: Date;
  stalePolicy?: Partial<StaleAccountPolicy>;
  budget?: Partial<DirectoryBudget>;
  includeSessions?: boolean;
}

interface FindingDraft {
  ruleId: string;
  title: string;
  description: string;
  severity: NormalizedFinding["severity"];
  confidence: number;
  objectId?: string;
  objectType?: string;
  host?: string;
  evidence: string;
  controlId?: string;
}

function buildFinding(ctx: DirectoryAnalysisContext, draft: FindingDraft): NormalizedFinding {
  return {
    title: sanitizeDirectoryText(draft.title, 300),
    description: sanitizeDirectoryText(draft.description, 2000),
    severity: draft.severity,
    confidence: draft.confidence,
    references: [],
    sourceTool: ctx.toolSlug,
    sourceFingerprint: directoryFingerprint({
      domainRef: ctx.domainRef, ruleId: draft.ruleId,
      ...(draft.objectId ? { objectId: draft.objectId } : {}),
      ...(draft.objectType ? { objectType: draft.objectType } : {}),
    }),
    ruleId: draft.ruleId,
    ...(draft.controlId ? { controlId: draft.controlId } : {}),
    directoryDomainRef: ctx.domainRef,
    ...(ctx.domainId ? { directoryDomainId: ctx.domainId } : {}),
    ...(draft.objectId ? { directoryObjectId: draft.objectId } : {}),
    ...(draft.objectType ? { directoryObjectType: draft.objectType } : {}),
    ...(draft.host ? { host: draft.host } : {}),
    evidence: sanitizeDirectoryText(draft.evidence, 1000),
    ...(directoryRemediation(draft.ruleId) ? { remediation: directoryRemediation(draft.ruleId) } : {}),
  };
}

/** Rule → control map for the AD baseline framework (§81): the seed
 *  catalog's control TITLES carry these rule ids so assessments link
 *  deterministically, exactly like P13/P14. PASS means the collected
 *  evidence satisfied the control — never a certification (§81). */
export const AD_RULE_CONTROLS: Record<string, { controlId: string; framework: string }> = {
  AD_PRIVILEGED_GROUP_EXCESS: { controlId: "MS-AD-1.1", framework: "MS_AD_BASELINE" },
  AD_NESTED_PRIVILEGED_GROUP: { controlId: "MS-AD-1.2", framework: "MS_AD_BASELINE" },
  AD_DANGEROUS_ACL: { controlId: "MS-AD-1.3", framework: "MS_AD_BASELINE" },
  AD_UNCONSTRAINED_DELEGATION: { controlId: "MS-AD-2.1", framework: "MS_AD_BASELINE" },
  AD_CONSTRAINED_DELEGATION_REVIEW: { controlId: "MS-AD-2.2", framework: "MS_AD_BASELINE" },
  AD_PREAUTH_NOT_REQUIRED: { controlId: "MS-AD-3.1", framework: "MS_AD_BASELINE" },
  AD_PASSWORD_NEVER_EXPIRES: { controlId: "MS-AD-3.2", framework: "MS_AD_BASELINE" },
  AD_PASSWORD_NOT_REQUIRED: { controlId: "MS-AD-3.3", framework: "MS_AD_BASELINE" },
  AD_STALE_ENABLED_ACCOUNT: { controlId: "MS-AD-3.4", framework: "MS_AD_BASELINE" },
  AD_DISABLED_PRIVILEGED_ACCOUNT: { controlId: "MS-AD-3.5", framework: "MS_AD_BASELINE" },
  AD_PASSWORD_POLICY_WEAK: { controlId: "MS-AD-3.6", framework: "MS_AD_BASELINE" },
  AD_LDAP_SIGNING_NOT_REQUIRED: { controlId: "MS-AD-4.1", framework: "MS_AD_BASELINE" },
  AD_LDAP_CHANNEL_BINDING_WEAK: { controlId: "MS-AD-4.2", framework: "MS_AD_BASELINE" },
  AD_SMB1_ENABLED: { controlId: "MS-AD-4.3", framework: "MS_AD_BASELINE" },
  AD_SMB_SIGNING_NOT_REQUIRED: { controlId: "MS-AD-4.4", framework: "MS_AD_BASELINE" },
  AD_SMB_ANONYMOUS_SHARE: { controlId: "MS-AD-4.5", framework: "MS_AD_BASELINE" },
  AD_SMB_WRITABLE_SHARE: { controlId: "MS-AD-4.6", framework: "MS_AD_BASELINE" },
  AD_TRUST_REVIEW: { controlId: "MS-AD-5.1", framework: "MS_AD_BASELINE" },
  AD_DC_SERVICE_EXPOSURE: { controlId: "MS-AD-5.2", framework: "MS_AD_BASELINE" },
  AD_KRBTGT_OLD: { controlId: "MS-AD-3.7", framework: "MS_AD_BASELINE" },
  ADCS_TEMPLATE_RISK: { controlId: "MS-AD-6.1", framework: "MS_AD_BASELINE" },
  ADCS_CA_CONFIGURATION: { controlId: "MS-AD-6.2", framework: "MS_AD_BASELINE" },
  AD_SPN_SERVICE_ACCOUNT: { controlId: "MS-AD-3.8", framework: "MS_AD_BASELINE" },
};

function controlFor(ctx: DirectoryAnalysisContext, ruleId: string, subjectRef: string, status: "PASS" | "FAIL", evidence: string): NormalizedControlAssessment | null {
  const mapping = AD_RULE_CONTROLS[ruleId];
  if (!mapping) return null;
  return {
    frameworkKey: mapping.framework, controlId: mapping.controlId, subjectRef,
    status, evidence: sanitizeDirectoryText(evidence, 500),
  };
}

export interface DirectoryPostureResult {
  findings: NormalizedFinding[];
  controlAssessments: NormalizedControlAssessment[];
  /** Identity annotations for persistence: privileged flags + risk
   *  scores are computed here so the store never re-derives them. */
  userAnnotations: Map<string, { privileged: boolean; privilegeEvidence: string[]; riskScore: number; riskFactors: Record<string, number | string> }>;
  computerAnnotations: Map<string, { riskScore: number; riskFactors: Record<string, number | string> }>;
  cyclesDetected: number;
}

const DAY_MS = 24 * 3600 * 1000;

function daysBetween(a: Date, b: Date): number {
  return Math.floor((a.getTime() - b.getTime()) / DAY_MS);
}

/**
 * The full AD posture analysis (§57–§78): privileged identity (§64),
 * nested groups (§65), ACLs (§66/§67), delegation (§59), Kerberos
 * posture (§57/§58), password policy (§60), account posture (§62/§63),
 * DC/LDAP posture (§70/§71), SMB posture (§43/§45), AD CS (§49/§50),
 * trusts (§25) and the explainable risk scores (§77/§78).
 */
export function analyzeDirectoryPosture(
  data: NormalizedDirectoryData,
  ctx: DirectoryAnalysisContext,
): DirectoryPostureResult {
  const now = ctx.now ?? new Date();
  const stalePolicy = clampStaleAccountPolicy(ctx.stalePolicy ?? DEFAULT_STALE_ACCOUNT_POLICY);
  const findings: NormalizedFinding[] = [];
  const assessments: NormalizedControlAssessment[] = [];
  const graph = buildIdentityGraph(data, ctx.domainRef);
  const resolution = resolveNestedGroups(graph, data.groups, { maxDepth: clampDirectoryBudget(ctx.budget).maxGraphDepth + 2 });
  const privileged = privilegedPrincipals(data, graph, resolution);
  const userByRef = new Map(data.users.map((u) => [u.objectId, u]));
  const groupByRef = new Map(data.groups.map((g) => [g.objectId, g]));

  const add = (draft: FindingDraft) => {
    findings.push(buildFinding(ctx, { ...draft, controlId: draft.controlId ?? AD_RULE_CONTROLS[draft.ruleId]?.controlId }));
    const assessment = controlFor(ctx, draft.ruleId, draft.objectId ?? ctx.domainRef, "FAIL", draft.evidence);
    if (assessment) assessments.push(assessment);
  };

  // §64/§22: privileged group hygiene — direct membership counts and
  // excessive membership. Effective membership (nested included) is
  // what the count measures; evidence names the group + count, never
  // a credential.
  for (const group of data.groups) {
    if (!isPrivilegedGroup({ objectId: group.objectId })) continue;
    const effective = resolution.effectiveMembers.get(group.objectId) ?? new Set<string>();
    const directMembers = data.relationships.filter(
      (e) => e.relationship === "MEMBER_OF" && e.toType === "GROUP" && e.toRef === group.objectId && e.fromType !== "GROUP",
    ).length;
    if (effective.size > 25) {
      add({
        ruleId: "AD_PRIVILEGED_GROUP_EXCESS",
        title: `Privileged group ${group.name} has excessive effective membership`,
        description: `${group.name} (privilege class ${group.privilegeClass}) resolves to ${effective.size} effective principal(s) including nested membership. Large standing privileged populations defeat tiered administration.`,
        severity: "HIGH", confidence: 0.95, objectId: group.objectId, objectType: "GROUP",
        evidence: `group ${group.name} sid=${group.objectId} directNonGroupMembers=${directMembers} effectiveMembers=${effective.size} (nested resolution bounded, cycles=${resolution.cyclesDetected})`,
      });
    }
    // §65: nesting INTO a privileged group is itself a review finding —
    // indirect privilege is easy to miss in manual review.
    const nestedFrom = data.relationships.filter(
      (e) => e.relationship === "MEMBER_OF" && e.toType === "GROUP" && e.toRef === group.objectId && e.fromType === "GROUP",
    );
    for (const edge of nestedFrom) {
      const child = groupByRef.get(edge.fromRef);
      add({
        ruleId: "AD_NESTED_PRIVILEGED_GROUP",
        title: `Group ${child?.name ?? edge.fromRef} is nested into privileged group ${group.name}`,
        description: `Members of ${child?.name ?? edge.fromRef} effectively hold ${group.name} privilege through nesting. Nested privilege paths must be intentional and documented.`,
        severity: "MEDIUM", confidence: 0.9, objectId: group.objectId, objectType: "GROUP",
        evidence: `MEMBER_OF edge ${edge.fromType}:${edge.fromRef} → GROUP:${edge.toRef} (source ${edge.source})`,
      });
    }
  }

  // §66/§67: dangerous ACL rights held by non-privileged principals
  // over high-value objects. Findings are per (principal, object);
  // raw ACL blobs never enter evidence.
  const highValueRefs = new Set<string>([
    ...(data.domain?.domainSid ? [data.domain.domainSid] : []),
    ...data.groups.filter((g) => isPrivilegedGroup({ objectId: g.objectId })).map((g) => g.objectId),
    ...data.computers.filter((c) => c.isDomainController).map((c) => c.objectId),
    ...data.groupPolicies.map((g) => g.objectId),
    ...data.certificateTemplates.map((t) => t.objectId ?? t.name),
  ]);
  for (const e of data.relationships) {
    if (!["GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"].includes(e.relationship)) continue;
    if (!highValueRefs.has(e.toRef)) continue;
    if (e.fromType === "GROUP" && isPrivilegedGroup({ objectId: e.fromRef })) continue;
    if (privileged.has(e.fromRef) && (e.fromType === "USER" || e.fromType === "SERVICE_ACCOUNT")) {
      // An already-privileged principal holding ACL rights is expected
      // administration surface, not a separate finding.
      continue;
    }
    add({
      ruleId: "AD_DANGEROUS_ACL",
      title: `${e.fromType} ${e.fromRef} holds ${e.relationship} over ${e.toType} ${e.toRef}`,
      description: `A principal outside the privileged set holds a write-class directory right (${e.relationship}) over a high-value object. Such rights can be exercised to take over the object or everything it controls. Analysis of collected ACL evidence only — no access was attempted.`,
      severity: e.relationship === "GENERIC_ALL" ? "CRITICAL" : "HIGH",
      confidence: 0.9, objectId: e.toRef, objectType: e.toType,
      evidence: `${e.relationship} edge ${e.fromType}:${e.fromRef} → ${e.toType}:${e.toRef} (source ${e.source}, confidence ${e.confidence})`,
    });
  }

  // §57–§63: per-account posture. Kerberos checks analyze METADATA
  // flags only (§61) — no ticket is ever requested.
  for (const user of data.users) {
    const isPriv = privileged.has(user.objectId);
    const principalLabel = user.displayName ?? user.samAccountName;
    if (user.delegationType === "UNCONSTRAINED") {
      add({
        ruleId: "AD_UNCONSTRAINED_DELEGATION",
        title: `Unconstrained delegation on account ${principalLabel}`,
        description: "The account is trusted for delegation to ANY service. Any service it runs under can reuse connecting users' credentials against arbitrary services.",
        severity: "HIGH", confidence: 0.95, objectId: user.objectId, objectType: "USER",
        evidence: `delegationType=UNCONSTRAINED sam=${user.samAccountName} (metadata analysis only — delegation was never exercised)`,
      });
    }
    if (user.delegationType === "CONSTRAINED") {
      add({
        ruleId: "AD_CONSTRAINED_DELEGATION_REVIEW",
        title: `Constrained delegation on account ${principalLabel} requires review`,
        description: `The account may delegate to: ${(user.delegationTargets ?? []).join(", ") || "(targets not recorded)"}. Confirm each target is still required and minimally scoped.`,
        severity: "LOW", confidence: 0.85, objectId: user.objectId, objectType: "USER",
        evidence: `delegationType=CONSTRAINED targets=${(user.delegationTargets ?? []).length}`,
      });
    }
    if (user.preauthNotRequired && user.enabled) {
      add({
        ruleId: "AD_PREAUTH_NOT_REQUIRED",
        title: `Kerberos pre-authentication disabled for ${principalLabel}`,
        description: "DONT_REQUIRE_PREAUTH is set on an enabled account. The platform records the CONFIGURATION only — no AS-REP material is ever requested (§57/§61).",
        severity: isPriv ? "HIGH" : "MEDIUM", confidence: 0.95, objectId: user.objectId, objectType: "USER",
        evidence: `preauthNotRequired=true enabled=true privileged=${isPriv}`,
      });
    }
    if (user.passwordNotRequired && user.enabled) {
      add({
        ruleId: "AD_PASSWORD_NOT_REQUIRED",
        title: `Account ${principalLabel} does not require a password`,
        description: "PASSWD_NOTREQD is set on an enabled account: it may authenticate without a password.",
        severity: "CRITICAL", confidence: 0.95, objectId: user.objectId, objectType: "USER",
        evidence: `passwordNotRequired=true enabled=true`,
      });
    }
    if (user.passwordNeverExpires && user.enabled && !user.isServiceAccount) {
      add({
        ruleId: "AD_PASSWORD_NEVER_EXPIRES",
        title: `Password never expires for ${principalLabel}`,
        description: "An interactive account is exempt from password expiry, so a single credential exposure remains valid indefinitely.",
        severity: isPriv ? "HIGH" : "MEDIUM", confidence: 0.9, objectId: user.objectId, objectType: "USER",
        evidence: `passwordNeverExpires=true privileged=${isPriv} serviceAccount=false`,
      });
    }
    // §58: SPN presence ALONE is inventory, not a vulnerability. The
    // finding fires only with compounding risk factors (long-lived
    // password, never-expires, privileged, or stale).
    if (user.spnPresent) {
      const pwdAge = user.passwordLastSetAt ? daysBetween(now, new Date(user.passwordLastSetAt)) : undefined;
      const factors: string[] = [];
      if (user.passwordNeverExpires) factors.push("password never expires");
      if (pwdAge !== undefined && pwdAge > 365) factors.push(`password age ${pwdAge}d`);
      if (isPriv) factors.push("account holds privileged access");
      if (factors.length > 0) {
        add({
          ruleId: "AD_SPN_SERVICE_ACCOUNT",
          title: `Service account ${principalLabel} carries SPN risk factors`,
          description: `The account exposes service principal name(s) (${(user.spns ?? []).join(", ")}) AND carries risk factors: ${factors.join("; ")}. SPN presence alone is not a finding (§58) — this fires only with the recorded factors. No Kerberos ticket was requested (§61).`,
          severity: isPriv ? "HIGH" : "MEDIUM", confidence: 0.85, objectId: user.objectId, objectType: "USER",
          evidence: `spns=${(user.spns ?? []).length} factors=${factors.join("; ")}`,
        });
      }
    }
    // §62/§63: stale enabled accounts against the ORG-CONFIGURABLE
    // threshold — never a hardcoded universal number.
    const lastActivity = user.lastLogonAt ?? user.passwordLastSetAt;
    if (user.enabled && lastActivity) {
      const idle = daysBetween(now, new Date(lastActivity));
      if (idle > stalePolicy.staleDays) {
        add({
          ruleId: "AD_STALE_ENABLED_ACCOUNT",
          title: `Enabled account ${principalLabel} is stale (${idle} days)`,
          description: `The account is enabled but shows no logon/password activity for ${idle} days, beyond the configured threshold of ${stalePolicy.staleDays} days (§63). Stale enabled accounts are standing access nobody watches.`,
          severity: isPriv && stalePolicy.escalatePrivileged ? "HIGH" : "MEDIUM",
          confidence: 0.8, objectId: user.objectId, objectType: "USER",
          evidence: `idleDays=${idle} thresholdDays=${stalePolicy.staleDays} privileged=${isPriv} lastActivity=${lastActivity}`,
        });
      }
    }
    if (!user.enabled && isPriv) {
      add({
        ruleId: "AD_DISABLED_PRIVILEGED_ACCOUNT",
        title: `Disabled account ${principalLabel} retains privileged membership`,
        description: "A disabled account still belongs to a privileged group (directly or nested); re-enabling it silently restores full privilege.",
        severity: "MEDIUM", confidence: 0.9, objectId: user.objectId, objectType: "USER",
        evidence: `enabled=false privilegedVia=${(privileged.get(user.objectId)?.via ?? []).join("; ")}`,
      });
    }
  }

  // §59: computer delegation (DCs are expected to delegate — excluded).
  for (const computer of data.computers) {
    if (computer.isDomainController) continue;
    if (computer.delegationType === "UNCONSTRAINED") {
      add({
        ruleId: "AD_UNCONSTRAINED_DELEGATION",
        title: `Unconstrained delegation on computer ${computer.hostname}`,
        description: "The computer is trusted for delegation to ANY service; a compromise or a coerced connection can expose reusable credentials of connecting users.",
        severity: "HIGH", confidence: 0.95, objectId: computer.objectId, objectType: "COMPUTER", host: computer.hostname,
        evidence: `delegationType=UNCONSTRAINED host=${computer.hostname} (metadata analysis only)`,
      });
    }
  }

  // §60: password policy vs the configured minimum baseline. The
  // baseline is a documented platform default (length ≥ 14, lockout
  // configured) — organizations tighten it through policy config.
  const policy = data.passwordPolicy ?? {};
  const minLength = typeof policy.minPasswordLength === "number" ? policy.minPasswordLength : undefined;
  const lockout = typeof policy.lockoutThreshold === "number" ? policy.lockoutThreshold : undefined;
  if (minLength !== undefined && minLength < 14) {
    add({
      ruleId: "AD_PASSWORD_POLICY_WEAK",
      title: `Domain password minimum length is ${minLength} (< 14)`,
      description: "The collected domain password policy permits passwords shorter than the 14-character baseline.",
      severity: "MEDIUM", confidence: 0.9, objectId: data.domain?.domainSid, objectType: "DOMAIN",
      evidence: `minPasswordLength=${minLength}`,
    });
  }
  if (lockout !== undefined && lockout === 0) {
    add({
      ruleId: "AD_PASSWORD_POLICY_WEAK",
      title: "Domain account lockout threshold is disabled (0)",
      description: "The collected domain password policy never locks accounts out, removing the online-guessing brake. (The platform itself never guesses credentials — §61/§120.)",
      severity: "MEDIUM", confidence: 0.9, objectId: data.domain?.domainSid, objectType: "DOMAIN",
      evidence: `lockoutThreshold=0`,
    });
  }

  // §62: krbtgt age from the well-known account when the collection
  // carried it (RID 502).
  const krbtgt = data.users.find((u) => /-502$/.test(u.objectId) || u.samAccountName.toLowerCase() === "krbtgt");
  if (krbtgt?.passwordLastSetAt) {
    const age = daysBetween(now, new Date(krbtgt.passwordLastSetAt));
    if (age > 365) {
      add({
        ruleId: "AD_KRBTGT_OLD",
        title: `KRBTGT password is ${age} days old`,
        description: "The KRBTGT account password has not been rotated within a year; Microsoft guidance is periodic double rotation.",
        severity: "MEDIUM", confidence: 0.85, objectId: krbtgt.objectId, objectType: "USER",
        evidence: `krbtgtPasswordAgeDays=${age}`,
      });
    }
  }

  // §70/§71: DC + LDAP posture from collected service metadata.
  for (const dc of data.domainControllers) {
    const svc = dc.services ?? {};
    const signing = svc.ldapSigningRequired;
    if (signing === false) {
      add({
        ruleId: "AD_LDAP_SIGNING_NOT_REQUIRED",
        title: `LDAP signing not required on ${dc.hostname}`,
        description: "The domain controller does not require LDAP signing, so unsigned LDAP sessions are accepted (configuration evidence collected read-only).",
        severity: "HIGH", confidence: 0.9, objectId: dc.objectId ?? dc.hostname, objectType: "DC", host: dc.hostname,
        evidence: `ldapSigningRequired=false dc=${dc.hostname}`,
      });
    }
    const binding = svc.ldapChannelBinding;
    if (binding === "never" || binding === false) {
      add({
        ruleId: "AD_LDAP_CHANNEL_BINDING_WEAK",
        title: `LDAP channel binding not enforced on ${dc.hostname}`,
        description: "LDAPS channel binding (EPA) is not enforced on the domain controller, per collected posture metadata.",
        severity: "MEDIUM", confidence: 0.85, objectId: dc.objectId ?? dc.hostname, objectType: "DC", host: dc.hostname,
        evidence: `ldapChannelBinding=${String(binding)} dc=${dc.hostname}`,
      });
    }
    if (svc.smb1Enabled === true) {
      add({
        ruleId: "AD_SMB1_ENABLED",
        title: `SMBv1 enabled on domain controller ${dc.hostname}`,
        description: "SMBv1 is enabled on a domain controller per collected service metadata.",
        severity: "HIGH", confidence: 0.9, objectId: dc.objectId ?? dc.hostname, objectType: "DC", host: dc.hostname,
        evidence: `smb1Enabled=true dc=${dc.hostname}`,
      });
    }
    if (svc.smbSigningRequired === false) {
      add({
        ruleId: "AD_SMB_SIGNING_NOT_REQUIRED",
        title: `SMB signing not required on ${dc.hostname}`,
        description: "SMB signing is not required on the domain controller per collected service metadata.",
        severity: "MEDIUM", confidence: 0.85, objectId: dc.objectId ?? dc.hostname, objectType: "DC", host: dc.hostname,
        evidence: `smbSigningRequired=false dc=${dc.hostname}`,
      });
    }
  }

  // §43/§45: SMB findings ONLY from collected share/protocol evidence.
  for (const share of data.smbShares) {
    if (share.smbDialect && /smb\s?1|1\.0/i.test(share.smbDialect)) {
      add({
        ruleId: "AD_SMB1_ENABLED",
        title: `SMBv1 dialect observed on ${share.host}`,
        description: `Share host ${share.host} negotiated/announced the SMB1 dialect for share ${share.shareName} (collected protocol metadata).`,
        severity: "HIGH", confidence: 0.85, objectId: `${share.host}/${share.shareName}`, objectType: "SMB_SHARE", host: share.host,
        evidence: `dialect=${share.smbDialect} share=${share.shareName} source=${share.source}`,
      });
    }
    if (share.anonymousAccess === true) {
      add({
        ruleId: "AD_SMB_ANONYMOUS_SHARE",
        title: `Share ${share.shareName} on ${share.host} allows anonymous access`,
        description: "The share was recorded as anonymously accessible by the bounded check (§44). Contents were never listed or downloaded (§97).",
        severity: share.accessLevel === "READ_WRITE" ? "HIGH" : "MEDIUM",
        confidence: 0.9, objectId: `${share.host}/${share.shareName}`, objectType: "SMB_SHARE", host: share.host,
        evidence: `anonymousAccess=true accessLevel=${share.accessLevel} source=${share.source}`,
      });
    }
    if (share.accessLevel === "READ_WRITE") {
      add({
        ruleId: "AD_SMB_WRITABLE_SHARE",
        title: `Share ${share.shareName} on ${share.host} is writable (READ_WRITE)`,
        description: "The share's recorded permission grants write access. Broadly writable shares are tampering/staging points — verify the grantee set is the intended one.",
        severity: "MEDIUM", confidence: 0.8, objectId: `${share.host}/${share.shareName}`, objectType: "SMB_SHARE", host: share.host,
        evidence: `accessLevel=READ_WRITE source=${share.source} (permission evidence only — no file was read or written)`,
      });
    }
  }

  // §25: trust review — missing SID filtering / selective auth on
  // trusts to domains outside this assessment.
  for (const trust of data.trusts) {
    if (trust.sidFilteringEnabled === false || trust.selectiveAuthentication === false) {
      add({
        ruleId: "AD_TRUST_REVIEW",
        title: `Trust to ${trust.targetDomainName} lacks SID filtering / selective authentication`,
        description: `The ${trust.direction} ${trust.trustType} trust to ${trust.targetDomainName} is recorded with sidFiltering=${String(trust.sidFilteringEnabled)} selectiveAuthentication=${String(trust.selectiveAuthentication)}. Cross-domain trust hardening must be verified.`,
        severity: "MEDIUM", confidence: 0.85, objectId: trust.targetDomainName, objectType: "DOMAIN",
        evidence: `trust target=${trust.targetDomainName} direction=${trust.direction} transitive=${trust.transitive}`,
      });
    }
  }

  // §49/§50: AD CS template + CA analysis (also exposed standalone).
  const adcs = analyzeAdcsPosture(data, ctx);
  findings.push(...adcs.findings);
  assessments.push(...adcs.controlAssessments);

  // ── Risk scores (§77/§78) — explainable factor sums ────────────────
  const userAnnotations: DirectoryPostureResult["userAnnotations"] = new Map();
  for (const user of data.users) {
    const factors: Record<string, number | string> = {};
    let score = 0;
    const isPriv = privileged.has(user.objectId);
    if (isPriv) { score += 40; factors.privilegedAccess = 40; }
    if (!user.enabled) { factors.enabled = "disabled (score held)"; }
    else {
      if (user.preauthNotRequired) { score += 15; factors.preauthNotRequired = 15; }
      if (user.passwordNeverExpires) { score += 10; factors.passwordNeverExpires = 10; }
      if (user.passwordNotRequired) { score += 25; factors.passwordNotRequired = 25; }
      if (user.delegationType === "UNCONSTRAINED") { score += 20; factors.unconstrainedDelegation = 20; }
      const lastActivity = user.lastLogonAt ?? user.passwordLastSetAt;
      if (lastActivity && daysBetween(now, new Date(lastActivity)) > stalePolicy.staleDays) { score += 10; factors.stale = 10; }
      if (user.spnPresent && user.passwordNeverExpires) { score += 5; factors.spnWithStaticPassword = 5; }
    }
    userAnnotations.set(user.objectId, {
      privileged: isPriv,
      privilegeEvidence: privileged.get(user.objectId)?.via ?? [],
      riskScore: Math.min(100, score),
      riskFactors: factors,
    });
  }
  const computerAnnotations: DirectoryPostureResult["computerAnnotations"] = new Map();
  for (const computer of data.computers) {
    const factors: Record<string, number | string> = {};
    let score = 0;
    if (computer.isDomainController) { score += 30; factors.domainController = 30; }
    if (computer.delegationType === "UNCONSTRAINED" && !computer.isDomainController) { score += 25; factors.unconstrainedDelegation = 25; }
    const adminEdges = data.relationships.filter((e) => e.relationship === "ADMIN_TO" && e.toType === "COMPUTER" && e.toRef === computer.objectId).length;
    if (adminEdges > 0) { const pts = Math.min(20, adminEdges * 4); score += pts; factors.adminPrincipals = pts; }
    // §78: a computer's score counts EXPOSURE + configuration only;
    // vulnerabilities of the host belong to the asset's own risk line
    // (correlated, never double-counted).
    factors.note = "configuration + exposure factors only; host vulnerabilities are scored on the network asset (§78)";
    computerAnnotations.set(computer.objectId, { riskScore: Math.min(100, score), riskFactors: factors });
  }

  return { findings, controlAssessments: assessments, userAnnotations, computerAnnotations, cyclesDetected: resolution.cyclesDetected };
}

// ── AD CS standalone analysis (§47–§50) ──────────────────────────────

export interface AdcsPostureResult {
  findings: NormalizedFinding[];
  controlAssessments: NormalizedControlAssessment[];
  /** Template name → governed risk classes (§50), for persistence. */
  templateRiskClasses: Map<string, string[]>;
}

const AUTH_EKUS = ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0"]; // client auth, smartcard logon, any-purpose

export function analyzeAdcsPosture(
  data: NormalizedDirectoryData,
  ctx: DirectoryAnalysisContext,
): AdcsPostureResult {
  const findings: NormalizedFinding[] = [];
  const assessments: NormalizedControlAssessment[] = [];
  const templateRiskClasses = new Map<string, string[]>();
  const privilegedRefs = new Set(
    data.relationships
      .filter((e) => ["GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS"].includes(e.relationship) && (e.toType === "CERTIFICATE_TEMPLATE" || e.toType === "CERTIFICATE_AUTHORITY"))
      .map((e) => `${e.toRef}:${e.fromRef}:${e.relationship}`),
  );

  for (const template of data.certificateTemplates as NormalizedCertificateTemplate[]) {
    const classes: string[] = [];
    const subject = (template.subjectConfig ?? {}) as Record<string, unknown>;
    const enrolleeSuppliesSubject = subject.enrolleeSuppliesSubject === true || subject.enrolleeSuppliesSubjectAltName === true;
    const ekus = template.authenticationEkus ?? [];
    const hasAuthEku = ekus.some((e) => AUTH_EKUS.includes(e)) || ekus.length === 0;
    const approval = template.managerApprovalRequired === true || (template.authorizedSignaturesRequired ?? 0) > 0;
    const perms = (template.enrollmentPermissions ?? {}) as Record<string, unknown>;
    const broadEnrollment = perms.broadLowPrivilegedEnrollment === true || perms.enrollPrincipals === "Authenticated Users" || perms.enrollPrincipals === "Domain Users";
    if (enrolleeSuppliesSubject && hasAuthEku && !approval) classes.push("ESC1");
    if ((ekus.includes("2.5.29.37.0") || ekus.length === 0) && broadEnrollment) classes.push("ESC2");
    if (ekus.includes("1.3.6.1.4.1.311.20.2.1") && !perms.applicationPoliciesRestricted) classes.push("ESC3");
    const dangerousAcl = [...privilegedRefs].some((k) => k.startsWith(`${template.objectId ?? template.name}:`));
    if (dangerousAcl) classes.push("ESC4");
    templateRiskClasses.set(template.name, classes);
    for (const cls of classes) {
      const governed = ADCS_RISK_CLASSES[cls]!;
      const draft: FindingDraft = {
        ruleId: "ADCS_TEMPLATE_RISK",
        title: `${cls}: ${template.name} — ${governed.title}`,
        description: `${governed.explanation} Affected template: ${template.name}.`,
        severity: governed.severity, confidence: 0.9,
        objectId: template.objectId ?? template.name, objectType: "TEMPLATE",
        evidence: `riskClass=${cls} enrolleeSuppliesSubject=${enrolleeSuppliesSubject} authEku=${hasAuthEku} managerApproval=${template.managerApprovalRequired ?? false} authorizedSignatures=${template.authorizedSignaturesRequired ?? 0} broadEnrollment=${broadEnrollment}`,
      };
      findings.push(buildFinding(ctx, { ...draft, controlId: AD_RULE_CONTROLS.ADCS_TEMPLATE_RISK.controlId }));
      const a = controlFor(ctx, "ADCS_TEMPLATE_RISK", template.objectId ?? template.name, "FAIL", draft.evidence);
      if (a) assessments.push(a);
    }
  }

  for (const ca of data.certificateAuthorities) {
    const meta = ca.metadata ?? {};
    const editFlags = typeof meta.editFlags === "string" ? meta.editFlags : "";
    if (/EDITF_ATTRIBUTESUBJECTALTNAME2/i.test(editFlags) || meta.userSpecifiedSan === "Enabled" || meta.userSpecifiedSan === true) {
      const draft: FindingDraft = {
        ruleId: "ADCS_CA_CONFIGURATION",
        title: `ESC6: CA ${ca.name} allows requester-specified SAN`,
        description: ADCS_RISK_CLASSES.ESC6.explanation,
        severity: "HIGH", confidence: 0.9, objectId: ca.name, objectType: "CA",
        evidence: `ca=${ca.name} editFlags=${editFlags || "(via userSpecifiedSan metadata)"}`,
      };
      findings.push(buildFinding(ctx, { ...draft, controlId: AD_RULE_CONTROLS.ADCS_CA_CONFIGURATION.controlId }));
      const a = controlFor(ctx, "ADCS_CA_CONFIGURATION", ca.name, "FAIL", draft.evidence);
      if (a) assessments.push(a);
    }
    if (meta.webEnrollmentEpa === false || meta.webEnrollment === "Enabled without EPA") {
      const draft: FindingDraft = {
        ruleId: "ADCS_CA_CONFIGURATION",
        title: `ESC8: CA ${ca.name} web enrollment without EPA metadata`,
        description: ADCS_RISK_CLASSES.ESC8.explanation,
        severity: "MEDIUM", confidence: 0.8, objectId: ca.name, objectType: "CA",
        evidence: `ca=${ca.name} webEnrollmentEpa=false (configuration metadata only — no relay attempted)`,
      };
      findings.push(buildFinding(ctx, { ...draft, controlId: AD_RULE_CONTROLS.ADCS_CA_CONFIGURATION.controlId }));
    }
  }
  return { findings, controlAssessments: assessments, templateRiskClasses };
}

/** LDAP posture as its own platform section (§71): DC service metadata
 *  only — a thin slice of the full posture analysis. */
export function analyzeLdapPosture(
  data: NormalizedDirectoryData,
  ctx: DirectoryAnalysisContext,
): NormalizedFinding[] {
  const subset: NormalizedDirectoryData = {
    ...data,
    users: [], groups: [], computers: [], trusts: [], smbShares: [],
    certificateAuthorities: [], certificateTemplates: [], relationships: [],
    organizationalUnits: [], groupPolicies: [],
  };
  return analyzeDirectoryPosture(subset, ctx).findings;
}

export type { NormalizedDirectoryGroup };
