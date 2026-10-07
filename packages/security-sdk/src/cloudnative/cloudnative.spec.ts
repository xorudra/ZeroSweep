import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { FixtureToolRunner, ToolRegistry } from "../index";
import {
  FalcoConnector, KubernetesConnector, classifyKubeHunterCheck, cloudNativeHealthBySlug,
  configurationFingerprint, createCloudNativeAdapters, detectImageDrift, evaluateContainerQualityGate,
  evaluateDeploymentSecurityGate, imageVulnerabilityFingerprint, isEndOfLifeKubernetes,
  kubeHunterCheckAllowed, parseCheckov, parseCycloneDxComponents, parseDockerBench, parseFalcoEvents,
  parseGrypeImage, parseKubeBench, parseKubeHunter, parseKubescape, parseSyft, parseTrivy, parseYamlDocuments,
  parseImageReference, assessKubernetesPosture, validateRegistryUrl, workloadsFromManifests,
  kubernetesDocuments, clampCloudNativeBudget, CLOUD_NATIVE_BUDGET_CAPS,
  FIXTURE_CHECKOV_OUTPUT, FIXTURE_CLUSTER_INVENTORY, FIXTURE_CYCLODX_SBOM, FIXTURE_DOCKER_BENCH_OUTPUT,
  FIXTURE_FAKE_IMAGE_SECRET, FIXTURE_FALCO_OUTPUT, FIXTURE_GRYPE_IMAGE_OUTPUT, FIXTURE_HOSTILE_YAML_ALIAS_BOMB,
  FIXTURE_HOSTILE_YAML_CUSTOM_TAG, FIXTURE_IMAGE_DIGEST, FIXTURE_IMAGE_DIGEST_DRIFTED, FIXTURE_IMAGE_REF,
  FIXTURE_K8S_MANIFEST_PRIVILEGED, FIXTURE_K8S_MANIFEST_SAFE, FIXTURE_KUBE_BENCH_OUTPUT,
  FIXTURE_KUBE_HUNTER_OUTPUT, FIXTURE_KUBESCAPE_OUTPUT, FIXTURE_SYFT_OUTPUT, FIXTURE_TRIVY_OUTPUT,
  type KubernetesTransport,
} from "../index";

/**
 * Prompt 13 fixture-lab tests (§94–§110). Everything runs over
 * recorded outputs and fixture manifests — no image is pulled or run,
 * no cluster is contacted, no registry is queried.
 */

describe("image identity (§5/§78)", () => {
  it("parses references with digest as strongest identity", () => {
    const ref = parseImageReference(`${FIXTURE_IMAGE_REF}@${FIXTURE_IMAGE_DIGEST}`);
    expect(ref.registry).toBe("registry.example.com");
    expect(ref.repository).toBe("team/webapp");
    expect(ref.tag).toBe("1.4.2");
    expect(ref.digest).toBe(FIXTURE_IMAGE_DIGEST);
    const hub = parseImageReference("nginx");
    expect(hub.registry).toBe("docker.io");
    expect(hub.repository).toBe("library/nginx");
  });

  it("rejects malformed references and digests instead of guessing", () => {
    expect(() => parseImageReference("UPPER/Case:1")).toThrow();
    expect(() => parseImageReference("repo/img@sha256:short")).toThrow();
    expect(() => parseImageReference("repo/img:bad tag")).toThrow();
  });

  it("detects tag→digest drift (§78)", () => {
    expect(detectImageDrift(FIXTURE_IMAGE_DIGEST, FIXTURE_IMAGE_DIGEST_DRIFTED)).toBe(true);
    expect(detectImageDrift(FIXTURE_IMAGE_DIGEST, FIXTURE_IMAGE_DIGEST)).toBe(false);
    expect(detectImageDrift(undefined, FIXTURE_IMAGE_DIGEST)).toBe(false);
  });
});

describe("registry URL policy (§7/§107)", () => {
  it("denies SSRF-class destinations and embedded credentials", () => {
    expect(validateRegistryUrl("https://ghcr.io").allowed).toBe(true);
    expect(validateRegistryUrl("http://ghcr.io").allowed).toBe(false);
    expect(validateRegistryUrl("https://user:pass@registry.example.com").reason).toContain("EMBEDDED_CREDENTIALS");
    expect(validateRegistryUrl("https://169.254.169.254").allowed).toBe(false);
    expect(validateRegistryUrl("https://localhost:5000").allowed).toBe(false);
    expect(validateRegistryUrl("https://10.0.0.5:5000").allowed).toBe(false);
    // §107 exception: an explicitly APPROVED internal registry passes.
    expect(validateRegistryUrl("https://10.0.0.5:5000", { approvedInternal: true }).allowed).toBe(true);
  });
});

describe("hostile YAML discipline (§49)", () => {
  it("rejects custom tags and alias bombs, parses plain manifests", () => {
    expect(() => parseYamlDocuments(FIXTURE_HOSTILE_YAML_CUSTOM_TAG)).toThrow(/rejected|YAML/);
    expect(() => parseYamlDocuments(FIXTURE_HOSTILE_YAML_ALIAS_BOMB)).toThrow();
    const docs = kubernetesDocuments(FIXTURE_K8S_MANIFEST_PRIVILEGED);
    expect(docs.map((d) => d.kind)).toEqual(["Deployment", "ClusterRoleBinding", "Secret"]);
  });

  it("enforces byte and document caps", () => {
    expect(() => parseYamlDocuments("x: 1", { maxBytes: 2, maxDocuments: 10, maxNodes: 100, maxDepth: 5 })).toThrow(/size/);
    expect(() => parseYamlDocuments("---\na: 1\n---\nb: 2", { maxBytes: 10000, maxDocuments: 1, maxNodes: 100, maxDepth: 5 })).toThrow(/document count/);
  });
});

describe("Trivy parser (§13–§18)", () => {
  const parsed = parseTrivy(FIXTURE_TRIVY_OUTPUT, { toolSlug: "trivy", imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST });

  it("separates vulnerabilities, misconfigurations and secrets (§16)", () => {
    const vulns = parsed.findings.filter((f) => f.cve);
    expect(vulns.map((f) => f.cve).sort()).toEqual(["CVE-2021-44228", "CVE-2023-0286"]);
    const config = parsed.findings.find((f) => f.ruleId === "AVD-DS-0002");
    expect(config?.origin).toBe("STATIC_CONFIGURATION_FINDING");
    expect(config?.cve).toBeUndefined();
    expect(parsed.controlAssessments.some((a) => a.controlId === "AVD-DS-0002" && a.status === "FAIL")).toBe(true);
  });

  it("distinguishes OS packages from language packages (§21) and binds layers (§22)", () => {
    const os = parsed.findings.find((f) => f.cve === "CVE-2023-0286");
    expect(os?.packageType).toBe("OS");
    expect(os?.layerDigest).toContain("sha256:");
    const lang = parsed.findings.find((f) => f.cve === "CVE-2021-44228");
    expect(lang?.packageType).toBe("LANGUAGE");
  });

  it("keeps fixed versions only from tool data (§24) and secrets metadata-only (§18)", () => {
    const os = parsed.findings.find((f) => f.cve === "CVE-2023-0286");
    expect(os?.fixedVersion).toBe("1.1.1t");
    const secret = parsed.findings.find((f) => f.secret);
    expect(secret?.secret?.detector).toBe("aws-access-key-id");
    expect(secret?.secret?.verificationStatus).toBe("NOT_VERIFIED");
    expect(JSON.stringify(parsed)).not.toContain(FIXTURE_FAKE_IMAGE_SECRET);
    expect(JSON.stringify(parsed)).not.toContain("aws_key =");
  });

  it("emits the static image record with config metadata (§5/§13)", () => {
    expect(parsed.images).toHaveLength(1);
    expect(parsed.images[0]?.digest).toBe(FIXTURE_IMAGE_DIGEST);
    expect(parsed.images[0]?.config?.entrypointPresent).toBe(true);
    expect(parsed.images[0]?.config?.envKeys).toEqual(["PATH", "APP_HOME"]);
  });
});

describe("cross-tool image correlation (§20/§95)", () => {
  it("Trivy and Grype produce the SAME fingerprint for the same CVE+package+digest", () => {
    const trivy = parseTrivy(FIXTURE_TRIVY_OUTPUT, { toolSlug: "trivy", imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST });
    const grype = parseGrypeImage(FIXTURE_GRYPE_IMAGE_OUTPUT, { toolSlug: "grype", imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST });
    const t = trivy.findings.find((f) => f.cve === "CVE-2023-0286");
    const g = grype.findings.find((f) => f.cve === "CVE-2023-0286");
    expect(t?.sourceFingerprint).toBe(g?.sourceFingerprint);
    expect(t?.sourceFingerprint).toBe(imageVulnerabilityFingerprint({
      imageDigest: FIXTURE_IMAGE_DIGEST, imageRef: FIXTURE_IMAGE_REF, cve: "CVE-2023-0286", packageName: "openssl", packageVersion: "1.1.1n",
    }));
    // A different digest is a DIFFERENT image observation (§5).
    const other = parseGrypeImage(FIXTURE_GRYPE_IMAGE_OUTPUT, { toolSlug: "grype", imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST_DRIFTED });
    expect(other.findings[0]?.sourceFingerprint).not.toBe(g?.sourceFingerprint);
  });
});

describe("Syft + SBOM import (§12–§14)", () => {
  it("inventories packages into the shared component shape", () => {
    const parsed = parseSyft(FIXTURE_SYFT_OUTPUT, { toolSlug: "syft", imageRef: FIXTURE_IMAGE_REF });
    expect(parsed.components.map((c) => c.purl).sort()).toEqual(["pkg:deb/debian/openssl@1.1.1n", "pkg:npm/lodash@4.17.20"]);
    expect(parsed.images[0]?.digest).toBe(FIXTURE_IMAGE_DIGEST);
  });

  it("imports CycloneDX SBOM components with PURL identity", () => {
    const components = parseCycloneDxComponents(FIXTURE_CYCLODX_SBOM);
    expect(components).toHaveLength(2);
    expect(components[0]?.licenses).toEqual(["OpenSSL"]);
  });
});

describe("benchmarks (§28–§41)", () => {
  it("docker-bench WARN becomes a finding + FAIL assessment; PASS stays evidence (§31/§56)", () => {
    const parsed = parseDockerBench(FIXTURE_DOCKER_BENCH_OUTPUT, { toolSlug: "docker-bench-for-security", hostRef: "docker-host-1" });
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]?.controlId).toBe("4.1");
    expect(parsed.controlAssessments.find((a) => a.controlId === "1.1.1")?.status).toBe("PASS");
    expect(parsed.findings.some((f) => f.controlId === "1.1.1")).toBe(false);
  });

  it("kube-bench FAIL becomes a CIS finding (§40/§41)", () => {
    const parsed = parseKubeBench(FIXTURE_KUBE_BENCH_OUTPUT, { toolSlug: "kube-bench", clusterRef: "fixture-cluster" });
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]?.controlId).toBe("1.1.12");
    expect(parsed.findings[0]?.origin).toBe("LIVE_CLUSTER_FINDING");
  });
});

describe("Kubescape + Checkov (§44–§47)", () => {
  it("kubescape failed controls bind to the §54 resource identity", () => {
    const hunter = parseKubeHunter(FIXTURE_KUBE_HUNTER_OUTPUT, { toolSlug: "kube-hunter", clusterRef: "fixture-cluster" });
    expect(hunter.findings.length).toBeGreaterThanOrEqual(1);
    expect(hunter.findings[0]?.sourceTool).toBe("kube-hunter");
    const parsed = parseKubescape(FIXTURE_KUBESCAPE_OUTPUT, { toolSlug: "kubescape", clusterRef: "fixture-cluster", origin: "LIVE_CLUSTER_FINDING" });
    expect(parsed.findings).toHaveLength(1);
    const f = parsed.findings[0]!;
    expect(f.namespace).toBe("prod");
    expect(f.resourceName).toBe("webapp");
    expect(f.sourceFingerprint).toBe(configurationFingerprint({ namespace: "prod", resourceKind: "Deployment", resourceName: "webapp", controlId: "C-0057" }));
  });

  it("checkov failures are static findings with file locations; passes are counted (§47)", () => {
    const parsed = parseCheckov(FIXTURE_CHECKOV_OUTPUT, { toolSlug: "checkov" });
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]?.origin).toBe("STATIC_CONFIGURATION_FINDING");
    expect(parsed.findings[0]?.filePath).toBe("k8s/deployment.yaml");
    expect(parsed.findings[0]?.namespace).toBe("default");
    expect(parsed.metrics.passedChecks).toBe(1);
  });
});

describe("kube-hunter policy (§42/§43)", () => {
  it("classifies checks and never allows intrusive automation", () => {
    expect(classifyKubeHunterCheck("api-server")).toBe("SAFE");
    expect(classifyKubeHunterCheck("pod-execution")).toBe("DISABLED");
    expect(classifyKubeHunterCheck("something-unlisted")).toBe("REVIEW_REQUIRED");
    expect(kubeHunterCheckAllowed("api-server")).toBe(true);
    expect(kubeHunterCheckAllowed("token-scope-probing")).toBe(false);
    expect(kubeHunterCheckAllowed("token-scope-probing", { approvedReview: true })).toBe(true);
    expect(kubeHunterCheckAllowed("pod-execution", { approvedReview: true })).toBe(false);
  });

  it("the adapter refuses to build an active-mode plan", async () => {
    const adapters = createCloudNativeAdapters(new FixtureToolRunner({}));
    const hunter = adapters.find((a) => a.metadata.slug === "kube-hunter")!;
    await expect(hunter.buildExecutionPlan(
      { type: "KUBERNETES_CLUSTER", value: "fixture-cluster", host: "fixture-cluster" },
      { hunterMode: "ACTIVE_HUNTING" },
    )).rejects.toThrow(/not automatable/);
    const plan = await hunter.buildExecutionPlan(
      { type: "KUBERNETES_CLUSTER", value: "fixture-cluster", host: "fixture-cluster" },
      { hunterMode: "PASSIVE_DISCOVERY" },
    );
    expect(plan.arguments.join(" ")).not.toContain("--active");
  });
});

describe("posture assessment (§38/§64–§73)", () => {
  const posture = assessKubernetesPosture({
    workloads: FIXTURE_CLUSTER_INVENTORY.workloads as never,
    roleBindings: FIXTURE_CLUSTER_INVENTORY.roleBindings as never,
    namespacesWithNetworkPolicy: FIXTURE_CLUSTER_INVENTORY.namespacesWithNetworkPolicy,
    namespaces: FIXTURE_CLUSTER_INVENTORY.namespaces,
    ingresses: FIXTURE_CLUSTER_INVENTORY.ingresses as never,
    kubernetesVersion: FIXTURE_CLUSTER_INVENTORY.version,
  }, { clusterRef: "fixture-cluster", origin: "LIVE_CLUSTER_FINDING" });

  it("flags the privileged workload, not the hardened one", () => {
    const flagged = new Set(posture.findings.map((f) => f.resourceName));
    expect(flagged.has("legacy-agent")).toBe(true);
    expect(flagged.has("webapp")).toBe(false);
    expect(posture.findings.some((f) => f.controlId === "KSV-0014" && f.severity === "CRITICAL")).toBe(true);
    expect(posture.findings.some((f) => f.controlId === "CIS-5.2.9")).toBe(true); // hostPath
    expect(posture.findings.some((f) => f.controlId === "KSV-0015")).toBe(true); // tag-only image
  });

  it("flags cluster-admin RBAC (§65) and treats internal no-policy namespaces as context (§66)", () => {
    expect(posture.findings.some((f) => f.controlId === "CIS-5.1.1")).toBe(true);
    const npDefault = posture.controlAssessments.find((a) => a.controlId === "CIS-5.3.2" && a.subjectRef.includes("default"));
    expect(npDefault?.status).toBe("WARN"); // internal-only: context, not a finding
    expect(posture.findings.some((f) => f.controlId === "CIS-5.3.2" && f.namespace === "default")).toBe(false);
  });

  it("records EOL cluster versions as WARN context only (§73)", () => {
    expect(isEndOfLifeKubernetes("1.24.0")).toBe(true);
    expect(isEndOfLifeKubernetes("1.29.4")).toBe(false);
    const v = assessKubernetesPosture({ workloads: [], kubernetesVersion: "1.24.0" }, { clusterRef: "c", origin: "LIVE_CLUSTER_FINDING" });
    expect(v.controlAssessments[0]?.status).toBe("WARN");
    expect(v.findings).toHaveLength(0);
  });
});

describe("manifest → workload inventory (§47/§52)", () => {
  it("derives posture inputs from manifests; Secret values never read (§36)", () => {
    const docs = kubernetesDocuments(FIXTURE_K8S_MANIFEST_PRIVILEGED);
    const { workloads, secretsMetadataOnly } = workloadsFromManifests(docs);
    expect(secretsMetadataOnly).toBe(1);
    expect(workloads).toHaveLength(1);
    expect(workloads[0]?.securityContext.privileged).toBe(true);
    expect(workloads[0]?.securityContext.hostPaths).toEqual(["/"]);
    expect(JSON.stringify(workloads)).not.toContain("Zml4dHVyZS"); // secret payload never surfaces
  });

  it("the hardened fixture workload produces zero posture findings", () => {
    const docs = kubernetesDocuments(FIXTURE_K8S_MANIFEST_SAFE);
    const { workloads } = workloadsFromManifests(docs);
    const result = assessKubernetesPosture({ workloads }, { clusterRef: "static", origin: "STATIC_CONFIGURATION_FINDING" });
    expect(result.findings).toHaveLength(0);
  });
});

describe("Falco ingestion (§57–§63)", () => {
  it("sanitizes hostile event fields and redacts secrets (§60)", () => {
    const parsed = parseFalcoEvents(FIXTURE_FALCO_OUTPUT, { toolSlug: "falco", clusterRef: "fixture-cluster" });
    expect(parsed.runtimeEvents).toHaveLength(2);
    const serialized = JSON.stringify(parsed);
    expect(serialized).not.toContain(FIXTURE_FAKE_IMAGE_SECRET);
    expect(serialized).not.toContain(String.fromCharCode(27));
    expect(parsed.runtimeEvents[0]?.namespace).toBe("prod");
  });

  it("correlation adds context, never an exploitation claim (§63)", () => {
    const falco = new FalcoConnector();
    const { events } = falco.ingest(FIXTURE_FALCO_OUTPUT, { clusterRef: "fixture-cluster" });
    const correlated = falco.correlate(events[0]!, FIXTURE_CLUSTER_INVENTORY.workloads as never);
    expect(correlated.note).toContain("not proof of exploitation");
  });
});

describe("quality + deployment gates (§75/§76)", () => {
  it("fails on KEV/critical/secret/privileged rules and passes clean input", () => {
    const dirty = evaluateContainerQualityGate({
      findings: [
        { severity: "CRITICAL", cve: "CVE-2021-44228", origin: "IMAGE_FINDING" },
        { severity: "HIGH", origin: "LIVE_CLUSTER_FINDING", controlId: "KSV-0014" },
      ],
      kevCves: ["CVE-2021-44228"],
    });
    expect(dirty.status).toBe("FAILED");
    expect(dirty.failedRules.join(" ")).toContain("KEV_IMAGE_VULNERABILITIES");
    expect(dirty.failedRules.join(" ")).toContain("PRIVILEGED_CONTAINERS");
    const clean = evaluateDeploymentSecurityGate({ findings: [], candidate: "webapp@sha256:abc" });
    expect(clean.status).toBe("PASSED");
    expect(clean.advisory).toContain("does not deploy or block");
  });
});

describe("budget clamps (§81) + adapter registry (§10/§93)", () => {
  it("budgets clamp to hard caps", () => {
    const budget = clampCloudNativeBudget({ maxImages: 999999 });
    expect(budget.maxImages).toBe(CLOUD_NATIVE_BUDGET_CAPS.maxImages);
  });

  it("registers the governed adapters; absent binaries are UNAVAILABLE, falco NOT_CONFIGURED", () => {
    const registry = new ToolRegistry();
    const adapters = createCloudNativeAdapters(new FixtureToolRunner({ trivy: { stdout: "{}", version: "0.58.0" } }));
    for (const a of adapters) registry.register(a);
    expect(registry.list()).toHaveLength(8);
    const health = cloudNativeHealthBySlug(adapters);
    expect(health.trivy).toBe("HEALTHY");
    expect(health.syft).toBe("UNAVAILABLE");
    expect(health.falco).toBe("NOT_CONFIGURED");
    expect(health["kubernetes-connector"]).toBe("NOT_CONFIGURED");
  });

  it("no adapter plan ever contains image-execution or socket operations (§9/§30)", async () => {
    const adapters = createCloudNativeAdapters(new FixtureToolRunner({}));
    for (const a of adapters) {
      const plan = await a.buildExecutionPlan(
        { type: "CONTAINER_IMAGE", value: FIXTURE_IMAGE_REF, host: "registry.example.com" },
        { imageRef: FIXTURE_IMAGE_REF, clusterId: "c-1", scanMode: "manifests", sourcePath: "/fixtures/src" },
      ).catch(() => null);
      if (!plan) continue;
      const surface = `${plan.executable ?? ""} ${plan.arguments.join(" ")}`;
      expect(surface).not.toMatch(/docker\s+run|docker\.sock|kubectl\s+(apply|exec|run)|--privileged/);
    }
  });
});

describe("Kubernetes connector (§34–§38)", () => {
  it("inventories + assesses posture; NOT_CONFIGURED without a registered cluster", async () => {
    const transport: KubernetesTransport = {
      async inventory() {
        return {
          version: FIXTURE_CLUSTER_INVENTORY.version,
          namespaces: FIXTURE_CLUSTER_INVENTORY.namespaces,
          workloads: FIXTURE_CLUSTER_INVENTORY.workloads as never,
          roleBindings: FIXTURE_CLUSTER_INVENTORY.roleBindings as never,
          namespacesWithNetworkPolicy: FIXTURE_CLUSTER_INVENTORY.namespacesWithNetworkPolicy,
          ingresses: FIXTURE_CLUSTER_INVENTORY.ingresses as never,
          secretMetadataCount: FIXTURE_CLUSTER_INVENTORY.secretMetadataCount,
        };
      },
    };
    const connector = new KubernetesConnector({
      clusters: { async getById(id) { return id === "cluster-1" ? { id, name: "fixture-cluster", apiServerReference: "fixture-apiserver" } : null; } },
      transport,
    });
    const target = { type: "KUBERNETES_CLUSTER" as const, value: "fixture-cluster", host: "fixture-cluster" };
    const plan = await connector.buildExecutionPlan(target, { clusterId: "cluster-1", inventoryMode: "POSTURE_ASSESSMENT" });
    const raw = await connector.execute(plan);
    const normalized = await connector.normalize(await connector.parse(raw.rawOutput ?? ""));
    expect(normalized.cloudNative?.workloads).toHaveLength(2);
    expect(normalized.findings.some((f) => f.controlId === "KSV-0014")).toBe(true);
    expect(normalized.metrics.secretsMetadataOnly).toBe(3);

    const unconfigured = new KubernetesConnector({
      clusters: { async getById() { return null; } }, transport,
    });
    const plan2 = await unconfigured.buildExecutionPlan(target, { inventoryMode: "POSTURE_ASSESSMENT" });
    await expect(unconfigured.execute(plan2)).rejects.toThrow(/NOT_CONFIGURED/);
  });
});

describe("docker socket discipline (§30/§106)", () => {
  it("docker-compose mounts no Docker socket into web/api/general/source workers", () => {
    const compose = readFileSync(resolve(process.cwd(), "../../docker-compose.yml"), "utf8");
    expect(compose.includes("docker.sock")).toBe(false);
  });
});
