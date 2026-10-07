/**
 * Prompt 15 — Active Directory engine tests (§104–§116).
 *
 * Fixture-only (§104): every payload is the fictional corp.example
 * dataset. The offensive-policy test (§112) and the credential-leak
 * test (§113) are the load-bearing safety proofs of this phase.
 */
import { describe, expect, it } from "vitest";
import { FixtureToolRunner, ToolRegistry } from "../index";
import {
  AD_DISABLED_REGISTRATIONS, ALL_DIRECTORY_SLUGS, CERTIPY_FORBIDDEN_ACTIONS,
  DIRECTORY_DISABLED_SLUGS, FIXTURE_BLOODHOUND_ACL_EXPORT, FIXTURE_BLOODHOUND_EXPORT, FIXTURE_CERTIPY_JSON,
  FIXTURE_CREDENTIAL_MARKER, FIXTURE_DC02_SID, FIXTURE_DOMAIN_RECORD, FIXTURE_DOMAIN_SID,
  FIXTURE_ENUM4LINUX_JSON, FIXTURE_GROUP_B_SID, FIXTURE_HOSTILE_USER, FIXTURE_NT_HASH_PAIR,
  FIXTURE_PINGCASTLE_XML, FIXTURE_SMBMAP_JSON, INERT_DIRECTORY_DEPS,
  SMBMAP_FORBIDDEN_FLAGS, analyzeAdcsPosture, analyzeDirectoryPosture, buildIdentityGraph,
  buildLdapBaseDn, buildSmbMapArgs, canonicalDirectoryRuleId, computeBlastRadius,
  createDirectoryAdapters, createFixtureDirectoryTransport, diffDirectorySnapshots,
  directoryFingerprint, directoryHealthBySlug, escapeLdapDnValue, escapeLdapFilterValue,
  evaluateSharpHoundCollectionPolicy, findAttackPaths, fixturePreviousBloodHoundExport,
  issueDirectoryLease, parseBloodHoundExport, parseCertipyFind, parseEnum4linuxNgOutput,
  parsePingCastleReport, parseSmbMapOutput, planAdRetest, privilegedPrincipals,
  registerDirectoryAdapters, resolveNestedGroups,
} from "../index";
import type { NormalizedDirectoryData } from "../index";
import { parseDirectoryPayload } from "./parsers-directory";
import { normalizeDirectoryCollection } from "./inventory";

// Import semantics (§31): an already-collected export is normalized
// whole — local-admin relationships included; SESSIONS stay dropped
// by default (§69).
const CTX = { domainDnsName: "corp.example", source: "bloodhound-connector", includeLocalAdmins: true };

function fixtureDirectory(): NormalizedDirectoryData {
  return parseBloodHoundExport(FIXTURE_BLOODHOUND_EXPORT, CTX).directory;
}

describe("Prompt 15 §105/§106 — LDAP + BloodHound fixture parsing", () => {
  it("normalizes users/groups/computers/DCs/trusts with provenance", () => {
    const { directory, counts } = parseBloodHoundExport(FIXTURE_BLOODHOUND_EXPORT, CTX);
    expect(counts.users).toBe(8);
    expect(counts.groups).toBe(6);
    expect(counts.computers).toBe(4);
    expect(directory.domainControllers.map((d) => d.hostname)).toEqual(["DC01", "DC02"]);
    expect(directory.trusts[0]?.targetDomainName).toBe("partner.example");
    expect(directory.domain?.domainSid).toBe(FIXTURE_DOMAIN_SID);
    const edge = directory.relationships.find((r) => r.relationship === "MEMBER_OF");
    expect(edge?.source).toBe("bloodhound-connector");
    expect(edge?.confidence).toBe("HIGH");
  });

  it("drops session edges by default and reports the drop (§69)", () => {
    const without = parseBloodHoundExport(FIXTURE_BLOODHOUND_EXPORT, CTX);
    expect(without.sessionsDropped).toBe(1);
    expect(without.directory.relationships.some((r) => r.relationship === "HAS_SESSION")).toBe(false);
    const withSessions = parseBloodHoundExport(FIXTURE_BLOODHOUND_EXPORT, { ...CTX, includeSessions: true });
    expect(withSessions.directory.relationships.some((r) => r.relationship === "HAS_SESSION")).toBe(true);
  });

  it("parses LDAP entries with UAC flag decoding (§105)", () => {
    const data = parseDirectoryPayload(JSON.stringify([
      { dn: "CN=Eve,DC=corp,DC=example", objectClass: ["top", "person", "user"], objectSid: "S-1-5-21-1-2-3-2001", sAMAccountName: "eve2", userAccountControl: 0x400000 + 0x10000 + 2, servicePrincipalName: ["HTTP/x.corp.example"] },
      { dn: "CN=Grp,DC=corp,DC=example", objectClass: ["top", "group"], objectSid: "S-1-5-21-1-2-3-512", name: "Domain Admins", member: ["CN=Eve,DC=corp,DC=example"] },
    ]), "ldap-json", CTX);
    const user = data.users[0]!;
    expect(user.enabled).toBe(false); // ACCOUNTDISABLE bit
    expect(user.preauthNotRequired).toBe(true);
    expect(user.passwordNeverExpires).toBe(true);
    expect(user.spnPresent).toBe(true);
    expect(data.groups[0]?.privilegeClass).toBe("PRIVILEGED"); // SID RID -512, not the name
    expect(data.relationships.some((r) => r.relationship === "MEMBER_OF")).toBe(true);
  });
});

describe("Prompt 15 §107/§108 — attack paths + cycles", () => {
  it("finds User A → Group B → Admin → Critical Computer C as analysis only", () => {
    const data = fixtureDirectory();
    const graph = buildIdentityGraph(data, "corp.example");
    const resolution = resolveNestedGroups(graph, data.groups);
    const paths = findAttackPaths(data, graph, resolution, {}, "corp.example");
    const path = paths.find((p) => p.targetRef === FIXTURE_DC02_SID && p.steps[0]?.ref !== FIXTURE_GROUP_B_SID)
      ?? paths.find((p) => p.targetRef === FIXTURE_DC02_SID);
    expect(path).toBeDefined();
    const labels = path!.steps.map((s) => s.ref);
    expect(labels[labels.length - 1]).toBe(FIXTURE_DC02_SID);
    expect(path!.steps.some((s) => s.ref === FIXTURE_GROUP_B_SID)).toBe(true);
    expect(path!.steps.some((s) => s.via === "ADMIN_TO")).toBe(true);
    expect(["THEORETICAL", "EVIDENCE_BACKED"]).toContain(path!.status);
    expect(path!.status).not.toBe("COMPROMISED");
    expect(path!.riskScore).toBeGreaterThan(0);
    expect(path!.riskFactors.pathLength).toBeDefined();
  });

  it("terminates on the Group A → Group B → Group A cycle (§108)", () => {
    const data = fixtureDirectory();
    const graph = buildIdentityGraph(data, "corp.example");
    const resolution = resolveNestedGroups(graph, data.groups);
    expect(resolution.cyclesDetected).toBeGreaterThan(0);
    // Eve is effectively a member of both cycle groups despite the loop.
    const cycleA = [...(resolution.effectiveMembers.get(`${FIXTURE_DOMAIN_SID}-1301`) ?? [])];
    expect(cycleA.length).toBeGreaterThan(0);
  });

  it("blast radius shows reach with the §76 framing, never compromise", () => {
    const data = fixtureDirectory();
    const graph = buildIdentityGraph(data, "corp.example");
    const radius = computeBlastRadius(data, graph, `${FIXTURE_DOMAIN_SID}-1101`);
    expect(radius.framing).toContain("does not imply");
    expect(radius.privilegedGroupsReached.length + radius.highValueTargetsReached.length).toBeGreaterThan(0);
  });

  it("privileged principals include nested membership with evidence (§64)", () => {
    const data = fixtureDirectory();
    const graph = buildIdentityGraph(data, "corp.example");
    const resolution = resolveNestedGroups(graph, data.groups);
    const privileged = privilegedPrincipals(data, graph, resolution);
    // Dave reaches Domain Admins only through Helpdesk nesting.
    const dave = privileged.get(`${FIXTURE_DOMAIN_SID}-1106`);
    expect(dave).toBeDefined();
    expect(dave!.via.join(" ")).toMatch(/DOMAIN ADMINS/i);
  });
});

describe("Prompt 15 §57–§67 — posture analysis", () => {
  it("produces evidence-backed findings across the posture families", () => {
    const data = fixtureDirectory();
    const result = analyzeDirectoryPosture(data, { domainRef: "corp.example", toolSlug: "ldap-directory-connector", now: new Date() });
    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules.has("AD_UNCONSTRAINED_DELEGATION")).toBe(true); // WEB01
    expect(rules.has("AD_PREAUTH_NOT_REQUIRED")).toBe(true); // carol
    expect(rules.has("AD_STALE_ENABLED_ACCOUNT")).toBe(true); // bob-stale vs default 90d
    expect(rules.has("AD_SPN_SERVICE_ACCOUNT")).toBe(true); // svc-web: SPN + never-expires + old password
    expect(rules.has("AD_NESTED_PRIVILEGED_GROUP")).toBe(true); // Helpdesk → Domain Admins
    expect(rules.has("AD_LDAP_SIGNING_NOT_REQUIRED")).toBe(true); // DC01 metadata
    expect(rules.has("AD_SMB1_ENABLED")).toBe(true);
    expect(rules.has("AD_PASSWORD_POLICY_WEAK")).toBe(true); // length 7 + lockout 0
    expect(rules.has("AD_TRUST_REVIEW")).toBe(true); // SID filtering off
    expect(rules.has("AD_KRBTGT_OLD")).toBe(true); // 800 days
    for (const f of result.findings) {
      expect(f.directoryDomainRef).toBe("corp.example");
      expect((f.evidence ?? '').length).toBeGreaterThan(0);
      expect(f.sourceFingerprint).toHaveLength(64);
    }
    // SPN presence ALONE (no risk factors) is NOT a finding (§58): the
    // fixture's svc-web is the only SPN account and it has factors.
    const spnFindings = result.findings.filter((f) => f.ruleId === "AD_SPN_SERVICE_ACCOUNT");
    expect(spnFindings).toHaveLength(1);
    // Risk scores are explainable factor maps (§77).
    const svc = result.userAnnotations.get(`${FIXTURE_DOMAIN_SID}-1102`);
    expect(svc?.riskFactors.passwordNeverExpires).toBe(10);
    // Control assessments exist as evidence (§81 — the API layer adds
    // the no-certification disclaimer; PASS is never claimed here).
    expect(result.controlAssessments.length).toBeGreaterThan(0);
    expect(result.controlAssessments.every((a) => a.status === "FAIL")).toBe(true);
  });

  it("flags dangerous ACL rights over high-value objects (§66/§67)", () => {
    const { directory } = parseBloodHoundExport(FIXTURE_BLOODHOUND_ACL_EXPORT, CTX);
    const result = analyzeDirectoryPosture(directory, { domainRef: "corp.example", toolSlug: "bloodhound-connector" });
    const acl = result.findings.find((f) => f.ruleId === "AD_DANGEROUS_ACL");
    expect(acl).toBeDefined();
    expect(acl?.severity).toBe("CRITICAL"); // GENERIC_ALL
    expect(acl?.evidence).toContain("GENERIC_ALL");
  });

  it("respects the organization-configured stale threshold (§63)", () => {
    const data = fixtureDirectory();
    const strict = analyzeDirectoryPosture(data, { domainRef: "corp.example", toolSlug: "x", stalePolicy: { staleDays: 1000 } });
    expect(strict.findings.some((f) => f.ruleId === "AD_STALE_ENABLED_ACCOUNT")).toBe(false);
  });
});

describe("Prompt 15 §109 — PingCastle import", () => {
  it("preserves the PingCastle score separately and maps canonical rules", () => {
    const result = parsePingCastleReport(FIXTURE_PINGCASTLE_XML, CTX);
    expect(result.pingcastleScore).toBe(55);
    expect(result.rules).toHaveLength(2);
    expect(result.findings).toHaveLength(1); // zero-point rule never becomes a finding
    const finding = result.findings[0]!;
    expect(finding.ruleId).toBe("AD_KRBTGT_OLD"); // canonical mapping (§109)
    expect(finding.sourceTool).toBe("pingcastle");
    expect(finding.evidence).toContain("preserved separately");
    // The same canonical issue from native analysis shares the
    // fingerprint: AD_KRBTGT_OLD is a domain-singleton rule, so the
    // object id is excluded from both fingerprints (§109 convergence).
    const native = analyzeDirectoryPosture(fixtureDirectory(), { domainRef: "corp.example", toolSlug: "ldap-directory-connector" });
    const nativeKrbtgt = native.findings.find((f) => f.ruleId === "AD_KRBTGT_OLD");
    expect(nativeKrbtgt?.sourceFingerprint).toBe(finding.sourceFingerprint);
    expect(nativeKrbtgt?.sourceFingerprint).toBe(directoryFingerprint({ domainRef: "corp.example", ruleId: "AD_KRBTGT_OLD" }));
    expect(canonicalDirectoryRuleId("pingcastle:krbtgt")).toBe("AD_KRBTGT_OLD");
  });

  it("rejects XXE PingCastle input", () => {
    const attack = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><PingCastleData>&xxe;</PingCastleData>`;
    expect(() => parsePingCastleReport(attack, CTX)).toThrow();
  });
});

describe("Prompt 15 §110/§111 — SMB + AD CS fixtures", () => {
  it("SMB: shares + permissions only, anonymous/writable findings from evidence", () => {
    const { shares } = parseSmbMapOutput(FIXTURE_SMBMAP_JSON, CTX);
    expect(shares).toHaveLength(3);
    expect(shares.find((s) => s.shareName === "Finance")?.accessLevel).toBe("NONE");
    const enumParsed = parseEnum4linuxNgOutput(FIXTURE_ENUM4LINUX_JSON, CTX);
    expect(enumParsed.services[0]?.detail).toContain("SMB 1.0");
    const merged: NormalizedDirectoryData = {
      ...fixtureDirectory(),
      smbShares: [...shares, ...enumParsed.shares.map((s) => ({ ...s }))],
    };
    const result = analyzeDirectoryPosture(merged, { domainRef: "corp.example", toolSlug: "smbmap" });
    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules.has("AD_SMB_ANONYMOUS_SHARE")).toBe(true);
    expect(rules.has("AD_SMB_WRITABLE_SHARE")).toBe(true);
    expect(rules.has("AD_SMB1_ENABLED")).toBe(true);
  });

  it("SMBMap plan can never contain download/upload/exec/search flags (§44)", () => {
    const args = buildSmbMapArgs("FILE01.CORP.EXAMPLE");
    for (const forbidden of SMBMAP_FORBIDDEN_FLAGS) expect(args).not.toContain(forbidden);
    expect(args).toEqual(["-H", "FILE01.CORP.EXAMPLE", "-P", "445", "-q"]);
  });

  it("AD CS: ESC classes from template/CA metadata, never exploited (§50)", () => {
    const parsed = parseCertipyFind(FIXTURE_CERTIPY_JSON, CTX);
    expect(parsed.certificateAuthorities).toHaveLength(1);
    const data: NormalizedDirectoryData = {
      ...fixtureDirectory(), users: [], groups: [], computers: [], relationships: [],
      certificateAuthorities: parsed.certificateAuthorities, certificateTemplates: parsed.certificateTemplates,
    };
    const adcs = analyzeAdcsPosture(data, { domainRef: "corp.example", toolSlug: "certipy-posture" });
    expect(adcs.templateRiskClasses.get("VulnTemplate (fixture)")).toContain("ESC1");
    expect(adcs.templateRiskClasses.get("Standard User (fixture)")).toEqual([]);
    const titles = adcs.findings.map((f) => f.title).join(" ");
    expect(titles).toContain("ESC1");
    expect(titles).toContain("ESC6");
  });

  it("Certipy adapter refuses every non-find action (§48)", async () => {
    const adapters = createDirectoryAdapters(new FixtureToolRunner({}), INERT_DIRECTORY_DEPS);
    const certipy = adapters.find((a) => a.metadata.slug === "certipy-posture")!;
    for (const action of CERTIPY_FORBIDDEN_ACTIONS) {
      await expect(certipy.validateConfiguration({ action })).rejects.toThrow(/refused/);
    }
    await expect(certipy.validateConfiguration({ action: "find" })).resolves.toBeUndefined();
  });
});

describe("Prompt 15 §112 — offensive tool policy (load-bearing)", () => {
  it("no offensive slug is registered as an executable adapter", () => {
    const adapters = createDirectoryAdapters(new FixtureToolRunner({}), INERT_DIRECTORY_DEPS);
    const slugs = adapters.map((a) => a.metadata.slug);
    for (const disabled of DIRECTORY_DISABLED_SLUGS) expect(slugs).not.toContain(disabled);
    expect(slugs.sort()).toEqual([...ALL_DIRECTORY_SLUGS].sort());
    // The registrations themselves are DISABLED descriptors.
    for (const reg of AD_DISABLED_REGISTRATIONS) {
      expect(reg.status).toBe("DISABLED");
      expect(reg.enabled).toBe(false);
    }
  });

  it("health reports DISABLED for offensive tools and NOT_CONFIGURED for unwired connectors", async () => {
    const adapters = createDirectoryAdapters(new FixtureToolRunner({}), INERT_DIRECTORY_DEPS);
    const health = await directoryHealthBySlug(adapters, INERT_DIRECTORY_DEPS);
    expect(health.get("responder")?.status).toBe("DISABLED");
    expect(health.get("kerbrute")?.status).toBe("DISABLED");
    expect(health.get("impacket")?.status).toBe("DISABLED");
    expect(health.get("ldap-directory-connector")?.status).toBe("NOT_CONFIGURED");
  });

  it("SharpHound collection policy: SAFE default, REVIEW_REQUIRED gated, unknown DISABLED (§29)", () => {
    const safe = evaluateSharpHoundCollectionPolicy(["MEMBERSHIP", "ACL", "TRUSTS"]);
    expect(safe.allowed).toBe(true);
    const sessions = evaluateSharpHoundCollectionPolicy(["MEMBERSHIP", "SESSIONS"]);
    expect(sessions.allowed).toBe(false);
    expect(sessions.denied[0]?.classification).toBe("REVIEW_REQUIRED");
    const approved = evaluateSharpHoundCollectionPolicy(["SESSIONS"], { allowReviewRequired: true });
    expect(approved.allowed).toBe(true);
    const unknown = evaluateSharpHoundCollectionPolicy(["CREDENTIAL_THEFT"]);
    expect(unknown.allowed).toBe(false);
    expect(unknown.denied[0]?.classification).toBe("DISABLED");
  });

  it("ldapsearch refuses arbitrary filters and non-governed query kinds (§14)", async () => {
    const adapters = createDirectoryAdapters(new FixtureToolRunner({}), INERT_DIRECTORY_DEPS);
    const ldapsearch = adapters.find((a) => a.metadata.slug === "ldapsearch")!;
    await expect(ldapsearch.validateConfiguration({ filter: "(objectClass=*)" })).rejects.toThrow(/forbidden/);
    await expect(ldapsearch.validateConfiguration({ queryKind: "RAW" })).rejects.toThrow(/not a governed query kind/);
    await expect(ldapsearch.validateConfiguration({ password: "x" })).rejects.toThrow(/forbidden/);
    await expect(ldapsearch.validateConfiguration({ queryKind: "USERS", credentialReference: "vault:ad/reader" })).resolves.toBeUndefined();
  });

  it("PingCastle refuses non-healthcheck modes (§38)", async () => {
    const adapters = createDirectoryAdapters(new FixtureToolRunner({}), INERT_DIRECTORY_DEPS);
    const pingcastle = adapters.find((a) => a.metadata.slug === "pingcastle")!;
    await expect(pingcastle.validateConfiguration({ mode: "conquest" })).rejects.toThrow(/healthcheck mode only/);
  });
});

describe("Prompt 15 §113/§114/§115 — credential leak, LDAP injection, hostile data", () => {
  it("credential material planted in fixtures appears NOWHERE in normalized output (§113)", () => {
    const { directory } = parseBloodHoundExport(FIXTURE_BLOODHOUND_EXPORT, CTX);
    const serialized = JSON.stringify(directory);
    expect(serialized).not.toContain(FIXTURE_CREDENTIAL_MARKER);
    expect(serialized).not.toContain(FIXTURE_NT_HASH_PAIR);
    const normalized = normalizeDirectoryCollection(directory, {});
    expect(JSON.stringify(normalized)).not.toContain(FIXTURE_CREDENTIAL_MARKER);
    const posture = analyzeDirectoryPosture(directory, { domainRef: "corp.example", toolSlug: "bloodhound-connector" });
    expect(JSON.stringify(posture.findings)).not.toContain(FIXTURE_CREDENTIAL_MARKER);
    expect(JSON.stringify(posture.findings)).not.toContain("31d6cfe0d16ae931b73c59d7e0c089c0");
  });

  it("LDAP filter/DN escaping neutralizes injection (§114)", () => {
    expect(escapeLdapFilterValue("a*b(c)d\\e")).toBe("a\\2ab\\28c\\29d\\5ce");
    expect(escapeLdapFilterValue("normal")).toBe("normal");
    expect(escapeLdapFilterValue("x\u0000y")).toBe("x\\00y");
    expect(escapeLdapDnValue("a,b+c")).toBe("a\\,b\\+c");
    expect(buildLdapBaseDn("corp.example", "TRUSTS")).toBe("CN=System,DC=corp,DC=example");
    expect(() => buildLdapBaseDn("corp example; rm -rf", "USERS")).toThrow();
  });

  it("hostile directory strings are sanitized and bounded (§115)", () => {
    const { directory } = parseBloodHoundExport({ users: [FIXTURE_HOSTILE_USER] }, CTX);
    const user = directory.users[0]!;
    expect(user.displayName ?? "").not.toContain("<script>");
    expect(user.displayName ?? "").not.toContain("\u001b");
    expect((user.displayName ?? "").length).toBeLessThanOrEqual(4096);
    expect(user.samAccountName).toBe("hostile");
  });

  it("directory leases carry references only and cap TTL at 3600s (§9)", () => {
    const lease = issueDirectoryLease({ directoryDomainId: "d1", credentialReference: "vault:ad/reader", ttlSeconds: 99999, now: new Date("2026-01-01T00:00:00Z") });
    expect(lease.expiresAt).toBe("2026-01-01T01:00:00.000Z");
    expect(JSON.stringify(lease)).not.toContain("password");
    expect(lease.credentialReference).toBe("vault:ad/reader");
  });
});

describe("Prompt 15 — connectors, drift, retest", () => {
  it("connectors report NOT_CONFIGURED with inert deps (never fabricate)", async () => {
    const registry = new ToolRegistry();
    const adapters = registerDirectoryAdapters(registry, new FixtureToolRunner({}), INERT_DIRECTORY_DEPS);
    const ldap = adapters.find((a) => a.metadata.slug === "ldap-directory-connector")!;
    const target = { type: "ACTIVE_DIRECTORY_DOMAIN" as const, value: "corp.example", host: "corp.example" };
    const plan = await ldap.buildExecutionPlan(target, { directoryDomainId: "missing" });
    await expect(ldap.execute(plan)).rejects.toThrow(/NOT_CONFIGURED/);
  });

  it("fixture transport collection flows through the BloodHound connector", async () => {
    const data = fixtureDirectory();
    const deps = {
      domains: { getDomain: async (id: string) => (id === FIXTURE_DOMAIN_RECORD.id ? FIXTURE_DOMAIN_RECORD : undefined) },
      transports: { bloodhound: createFixtureDirectoryTransport(data) },
    };
    const adapters = createDirectoryAdapters(new FixtureToolRunner({}), deps);
    const bh = adapters.find((a) => a.metadata.slug === "bloodhound-connector")!;
    const target = { type: "ACTIVE_DIRECTORY_DOMAIN" as const, value: "corp.example", host: "corp.example" };
    const plan = await bh.buildExecutionPlan(target, { directoryDomainId: FIXTURE_DOMAIN_RECORD.id, directoryDomainRef: "corp.example" });
    const { rawOutput } = await bh.execute(plan);
    const parsed = await bh.parse(rawOutput ?? "");
    const result = await bh.normalize(parsed);
    expect(result.directory?.users.length).toBe(8);
    expect(result.directory?.snapshot?.snapshotHash).toHaveLength(64);
    expect(result.metrics.users).toBe(8);
  });

  it("drift diff yields review signals for new privilege + new trust (§80)", () => {
    const previous = parseBloodHoundExport(fixturePreviousBloodHoundExport(), CTX).directory;
    const current = fixtureDirectory();
    const events = diffDirectorySnapshots(previous, current, "corp.example");
    const kinds = events.map((e) => e.kind);
    expect(kinds).toContain("NEW_PRIVILEGED_MEMBER");
    expect(kinds).toContain("NEW_TRUST");
    // §80: a change is never labelled malicious — the word may appear
    // only inside the explicit "not classified malicious" framing.
    for (const e of events) {
      if (/malicious/i.test(e.detail)) expect(e.detail).toContain("not classified malicious");
    }
    // First snapshot = baseline, no drift.
    expect(diffDirectorySnapshots(undefined, current, "corp.example")).toEqual([]);
  });

  it("retest plans are read-only and route by rule family (§84)", () => {
    expect(planAdRetest({ ruleId: "ADCS_TEMPLATE_RISK" }).adapterSlug).toBe("certipy-posture");
    expect(planAdRetest({ ruleId: "AD_SMB_ANONYMOUS_SHARE" }).stageType).toBe("SMB_POSTURE");
    expect(planAdRetest({ ruleId: "AD_LDAP_SIGNING_NOT_REQUIRED" }).section).toBe("LDAP_POSTURE");
    expect(planAdRetest({ ruleId: "AD_STALE_ENABLED_ACCOUNT" }).readOnly).toBe(true);
  });
});
