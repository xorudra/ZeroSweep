/**
 * Prompt 14 — cloud-security SDK tests (§88–§102): inventory
 * normalization per provider, IAM/storage/database/network/encryption/
 * logging analysis, CSPM parsers + canonical merging, Steampipe pack
 * governance, credential-reference discipline, SSRF denial, read-only
 * transport proof, drift diffing and the quality gate.
 */
import { describe, expect, it } from "vitest";
import {
  AWS_FIXTURE_INVENTORY, AZURE_FIXTURE_INVENTORY, CHECKOV_IAC_FIXTURE, GCP_FIXTURE_INVENTORY,
  HOSTILE_SECRET_FIXTURE, PROWLER_FIXTURE, ROADTOOLS_FIXTURE, SCOUTSUITE_FIXTURE, STEAMPIPE_FIXTURE_ROWS,
} from "./fixtures";
import { analyzeCloudInventory, analyzeIam } from "./analysis";
import { cloudFingerprint, evaluateCloudSecurityGate, iacLiveMatchKey, liveMatchKey } from "./correlation";
import { parseCheckov } from "../cloudnative/parsers-cloud";
import {
  cloudEndpointVerdict, isValidCredentialReference, looksLikeSecretValue, parseBoundedJson, parseIamPolicyDocument,
} from "./guards";
import { createFixtureCloudTransport, diffCloudInventories, normalizeProviderInventory } from "./inventory";
import {
  canonicalCloudRule, evaluateSteampipeQuery, parseProwler, parseRoadtools, parseScoutSuite, parseSteampipeRows,
} from "./parsers-cloudsec";
import { planCloudRetest } from "./retest";
import { CLOUD_SEC_SLUGS, PACU_DESCRIPTOR, createCloudSecAdapters } from "./registry";
import { issueCredentialLease, isLeaseActive } from "./types";

const AWS_CTX = { provider: "AWS" as const, accountId: "acct-1", accountRef: "123456789012", toolSlug: "aws-inventory" };

function awsData() {
  return normalizeProviderInventory("AWS", AWS_FIXTURE_INVENTORY, { accountId: "acct-1", accountRef: "123456789012", toolSlug: "aws-inventory" });
}

describe("inventory normalization (§13–§19)", () => {
  it("normalizes AWS resources with provider identity, exposure and snapshot hash", () => {
    const data = awsData();
    expect(data.resources.length).toBeGreaterThanOrEqual(10);
    const bucket = data.resources.find((r) => r.name === "public-assets-fixture")!;
    expect(bucket.resourceType).toBe("AWS_S3_BUCKET");
    expect(bucket.exposure).toBe("PUBLIC");
    expect(data.snapshot.snapshotHash).toMatch(/^[a-f0-9]{64}$/);
    expect(data.snapshot.regions).toContain("us-east-1");
    expect(data.relationships.some((r) => r.relationship === "MAPS_TO")).toBe(true); // EKS/ECR links (§50/§51)
  });

  it("keeps secret-manager + serverless metadata only — no values anywhere", () => {
    const text = JSON.stringify(awsData());
    expect(text).not.toContain("secret-value");
    const lambda = awsData().resources.find((r) => r.resourceType === "AWS_LAMBDA_FUNCTION")!;
    expect(lambda.configuration.envKeys).toEqual(["TABLE_NAME", "API_TOKEN"]); // key NAMES only (§52)
  });

  it("sanitizes hostile secret-shaped tag values (§99/§100)", () => {
    const data = normalizeProviderInventory("AWS", HOSTILE_SECRET_FIXTURE, { accountId: "a", accountRef: "x", toolSlug: "aws-inventory" });
    const serialized = JSON.stringify(data);
    expect(serialized).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(serialized).not.toContain("wJalrXUtnFEMI");
  });

  it("normalizes Azure + GCP inventories (§91/§92)", () => {
    const az = normalizeProviderInventory("AZURE", AZURE_FIXTURE_INVENTORY, { accountId: "a2", accountRef: "sub-1", toolSlug: "azure-inventory" });
    expect(az.resources.some((r) => r.resourceType === "AZURE_AKS_CLUSTER")).toBe(true);
    const gcp = normalizeProviderInventory("GCP", GCP_FIXTURE_INVENTORY, { accountId: "a3", accountRef: "proj-1", toolSlug: "gcp-inventory" });
    expect(gcp.resources.some((r) => r.resourceType === "GCP_GKE_CLUSTER")).toBe(true);
    const analysis = analyzeCloudInventory(gcp, { provider: "GCP", accountId: "a3", accountRef: "proj-1", toolSlug: "gcp-inventory" });
    expect(analysis.findings.some((f) => f.ruleId === "firewall-sensitive-port-world")).toBe(true);
  });
});

describe("provider-native analysis (§36–§57)", () => {
  it("produces the §90 AWS findings from configuration evidence", () => {
    const data = awsData();
    const { findings } = analyzeCloudInventory(data, AWS_CTX);
    const rules = findings.map((f) => f.ruleId);
    for (const rule of ["storage-public-access", "firewall-sensitive-port-world", "iam-admin-equivalent", "iam-broad-trust", "mfa-not-enabled", "database-public-access", "database-encryption", "audit-logging-disabled", "kms-rotation-disabled", "iam-long-lived-credentials", "serverless-public-access"]) {
      expect(rules).toContain(rule);
    }
    const sg = findings.find((f) => f.ruleId === "firewall-sensitive-port-world")!;
    expect(sg.severity).toBe("CRITICAL"); // SSH world-open
    expect(sg.findingClass).toBe("PUBLIC_EXPOSURE");
    expect(findings.find((f) => f.ruleId === "storage-public-access")!.cloudProvider).toBe("AWS");
    // The private bucket produces NO storage findings (§43 evidence-only).
    expect(findings.some((f) => f.providerResourceId === "arn:aws:s3:::private-data-fixture")).toBe(false);
  });

  it("emits CIS control assessments — PASS is evidence, never a finding (§68)", () => {
    const data = awsData();
    const { controlAssessments, findings } = analyzeCloudInventory(data, AWS_CTX);
    expect(controlAssessments.some((c) => c.frameworkKey === "CIS_AWS" && c.controlId === "2.1.2" && c.status === "FAIL")).toBe(true);
    expect(findings.every((f) => f.title.length > 0)).toBe(true);
  });

  it("IAM parser is bounded + wildcard-aware (§36/§42)", () => {
    const parsed = parseIamPolicyDocument(JSON.stringify({ Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }));
    expect(parsed.isAdministratorEquivalent).toBe(true);
    expect(parseIamPolicyDocument("{not json").statements).toEqual([]);
    expect(parseIamPolicyDocument("x".repeat(300 * 1024)).statements).toEqual([]); // oversize → empty, never throws
  });

  it("IAM section alone: stale claims require evidence (§39)", () => {
    const { findings } = analyzeIam([], AWS_CTX);
    expect(findings).toEqual([]);
  });
});

describe("CSPM parsers + canonical correlation (§23/§26/§60)", () => {
  it("Prowler: FAIL only — PASS never becomes a finding", () => {
    const findings = parseProwler(PROWLER_FIXTURE, { toolSlug: "prowler", provider: "AWS", accountId: "acct-1", accountRef: "123456789012" });
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.providerResourceId !== "arn:aws:s3:::private-data-fixture")).toBe(true);
  });

  it("Prowler + ScoutSuite + native on the same bucket share ONE fingerprint (§95)", () => {
    const ctx = { provider: "AWS" as const, accountId: "acct-1", accountRef: "123456789012" };
    const prowler = parseProwler(PROWLER_FIXTURE, { toolSlug: "prowler", ...ctx });
    const scout = parseScoutSuite(SCOUTSUITE_FIXTURE, { toolSlug: "scoutsuite", ...ctx });
    const native = analyzeCloudInventory(awsData(), { ...ctx, toolSlug: "aws-inventory" }).findings;
    const key = (fs: typeof prowler) => fs.find((f) => f.ruleId === "storage-public-access")!.sourceFingerprint;
    expect(key(prowler)).toBe(key(scout));
    expect(key(prowler)).toBe(key(native));
  });

  it("canonical rule mapping is conservative", () => {
    expect(canonicalCloudRule("s3_bucket_public_access", "s3")).toBe("storage-public-access");
    expect(canonicalCloudRule("some_unknown_check", "ec2")).toBe("some_unknown_check");
  });

  it("Steampipe: packs only, alarm rows only (§32)", () => {
    expect(evaluateSteampipeQuery({ sql: "select * from aws_s3_bucket" }).allowed).toBe(false);
    expect(evaluateSteampipeQuery({ packId: "aws-cis-foundations" }).allowed).toBe(true);
    expect(evaluateSteampipeQuery({ packId: "made-up-pack" }).allowed).toBe(false);
    const findings = parseSteampipeRows(STEAMPIPE_FIXTURE_ROWS, { toolSlug: "steampipe", provider: "AWS", accountId: "acct-1", accountRef: "123456789012" });
    expect(findings).toHaveLength(1); // the "ok" row is PASS evidence
  });

  it("ROADtools import is defensive-only (§29): privileged roles + app permissions", () => {
    const findings = parseRoadtools(ROADTOOLS_FIXTURE, { toolSlug: "roadtools", provider: "AZURE", accountId: "a2", accountRef: "sub-1" });
    expect(findings.map((f) => f.ruleId)).toEqual(expect.arrayContaining(["iam-admin-equivalent", "iam-wildcard-actions"]));
  });

  it("IaC/live correlation keys (§96): mapped rule + matching name merge; unmapped never merge", () => {
    const checkov = parseCheckov(JSON.stringify(CHECKOV_IAC_FIXTURE), { toolSlug: "checkov" });
    expect(checkov.findings).toHaveLength(1);
    const f = checkov.findings[0]!;
    expect(iacLiveMatchKey({ ruleId: f.ruleId, resourceName: f.resourceName })).toBe(
      liveMatchKey({ ruleId: "storage-public-access", resourceName: "public-assets-fixture" }),
    );
    expect(iacLiveMatchKey({ ruleId: "CKV_UNKNOWN_1", resourceName: "x" })).toBeNull();
  });
});

describe("safety discipline (§6/§93/§100/§101)", () => {
  it("credential references are names; values are rejected", () => {
    expect(isValidCredentialReference("vault:prod/aws/assessment-role")).toBe(true);
    expect(isValidCredentialReference("AKIAIOSFODNN7EXAMPLE")).toBe(false);
    expect(looksLikeSecretValue("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY00")).toBe(true);
  });

  it("cloud endpoints pass SSRF policy (§101): metadata + private denied", () => {
    expect(cloudEndpointVerdict("https://169.254.169.254/latest/meta-data").allowed).toBe(false);
    expect(cloudEndpointVerdict("https://10.0.0.5/admin").allowed).toBe(false);
    expect(cloudEndpointVerdict("http://management.azure.com/").allowed).toBe(false); // not https
    expect(cloudEndpointVerdict("https://management.azure.com/").allowed).toBe(true);
  });

  it("fixture transports expose no mutation surface (§93)", async () => {
    const transport = createFixtureCloudTransport("AWS", AWS_FIXTURE_INVENTORY);
    expect(transport.mutationCalls).toEqual([]);
    expect(Object.keys(transport).sort()).toEqual(["fetchInventory", "mutationCalls", "provider", "validateIdentity"]);
    const inv = await transport.fetchInventory({ id: "a", provider: "AWS", name: "fixture", externalAccountId: "123456789012" }, { includeRegions: [], excludeRegions: [], includeUnits: [], excludeUnits: [], includeResources: [], excludeResources: [] });
    expect(inv.resources?.length).toBeGreaterThan(0);
  });

  it("bounded JSON rejects oversize/deep payloads (§99)", () => {
    expect(() => parseBoundedJson("x".repeat(11 * 1024 * 1024))).toThrow();
    expect(() => parseBoundedJson(JSON.stringify({ a: 1 }))).not.toThrow();
  });

  it("credential leases are job-scoped and expire (§11)", () => {
    const now = new Date("2026-10-07T00:00:00Z");
    const lease = issueCredentialLease({ cloudAccountId: "a", credentialReference: "vault:x", now, ttlSeconds: 999999 });
    expect(new Date(lease.expiresAt).getTime() - now.getTime()).toBe(3600 * 1000); // capped at 1h
    expect(isLeaseActive(lease, new Date("2026-10-07T00:30:00Z"))).toBe(true);
    expect(isLeaseActive(lease, new Date("2026-10-07T02:00:00Z"))).toBe(false);
    expect(JSON.stringify(lease)).not.toContain("secret-value");
  });
});

describe("drift + gate + retest (§64/§70/§73)", () => {
  it("diffs inventories into drift items; removals are NOT_SEEN observations", () => {
    const before = awsData();
    const afterRaw = structuredClone(AWS_FIXTURE_INVENTORY);
    afterRaw.resources = (afterRaw.resources ?? []).filter((r) => r.name !== "orders-fixture");
    (afterRaw.resources.find((r) => r.name === "main-trail")!.config as Record<string, unknown>).enabled = true;
    const after = normalizeProviderInventory("AWS", afterRaw, { accountId: "acct-1", accountRef: "123456789012", toolSlug: "aws-inventory" });
    const items = diffCloudInventories(before, after);
    expect(items.some((i) => i.kind === "RESOURCE_REMOVED")).toBe(true);
    expect(items.some((i) => i.kind === "LOGGING_CHANGED")).toBe(true);
  });

  it("quality gate fails on critical public storage, warns on unobserved logging", () => {
    const verdict = evaluateCloudSecurityGate({
      findings: [{ severity: "CRITICAL", findingClass: "PUBLIC_EXPOSURE", resourceType: "AWS_S3_BUCKET" }],
      auditLoggingEnabled: null,
    });
    expect(verdict.status).toBe("FAILED");
    expect(verdict.failedRules).toContain("NO_PUBLIC_CRITICAL_STORAGE");
    expect(verdict.warningRules).toContain("AUDIT_LOGGING_NOT_OBSERVED");
  });

  it("retest plans target one resource + one section (§73)", () => {
    const plan = planCloudRetest({ cloudProvider: "AWS", providerResourceId: "arn:aws:s3:::b", ruleId: "storage-public-access" });
    expect(plan?.analysisSection).toBe("STORAGE_ANALYSIS");
    expect(plan?.stages).toContain("CLOUD_AUTH");
    expect(planCloudRetest({ cloudProvider: null })).toBeNull();
  });

  it("registry exposes the family + Pacu DISABLED, never as an adapter (§89)", () => {
    expect(CLOUD_SEC_SLUGS).not.toContain("pacu");
    expect(createCloudSecAdapters().map((a) => a.metadata.slug)).not.toContain("pacu");
    expect(PACU_DESCRIPTOR.status).toBe("DISABLED");
    expect(createCloudSecAdapters().map((a) => a.metadata.slug)).toEqual(expect.arrayContaining([...CLOUD_SEC_SLUGS]));
    expect(cloudFingerprint({ provider: "AWS", accountRef: "a", providerResourceId: "r", ruleId: "x", findingClass: "IAM_RISK" })).toMatch(/^cloud:[a-f0-9]{64}$/);
  });
});
