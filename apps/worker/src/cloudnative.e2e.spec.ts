import { describe, expect, it } from "vitest";
import {
  FIXTURE_CHECKOV_OUTPUT, FIXTURE_CLUSTER_INVENTORY, FIXTURE_DOCKER_BENCH_OUTPUT,
  FIXTURE_FAKE_IMAGE_SECRET, FIXTURE_GRYPE_IMAGE_OUTPUT, FIXTURE_IMAGE_DIGEST,
  FIXTURE_IMAGE_DIGEST_DRIFTED, FIXTURE_IMAGE_REF, FIXTURE_KUBE_BENCH_OUTPUT,
  FIXTURE_KUBESCAPE_OUTPUT, FIXTURE_SYFT_OUTPUT, FIXTURE_TRIVY_OUTPUT,
  FixtureToolRunner, KubernetesConnector, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  cloudNativeHealthBySlug, createCloudNativeAdapters, createCodeAdapters, codeHealthBySlug,
  type FixtureResponse, type KubernetesConnectorDeps,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore, TEST_SCOPE } from "./testing/fake-store";

/**
 * Prompt 13 end-to-end scenarios (§94–§110): the real cloud-native
 * adapters run the full pipeline over RECORDED tool outputs and the
 * fixture cluster inventory. No image is pulled or executed, no
 * cluster is contacted, no registry is queried, no Docker socket
 * exists. The fixture fake secret must appear NOWHERE in state (§101).
 */

const IMAGE_SCOPE = { includeHosts: ["registry.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] };
const CLUSTER_SCOPE = { includeHosts: ["fixture-cluster"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] };

function fixtureConnectorDeps(): KubernetesConnectorDeps {
  return {
    clusters: {
      async getById(id: string) {
        return id === "cluster-1" ? { id, name: "fixture-cluster", apiServerReference: "fixture-apiserver" } : null;
      },
    },
    transport: {
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
    },
  };
}

type CloudProfile = "CONTAINER_BASELINE" | "CONTAINER_MISCONFIG_ONLY" | "KUBERNETES_BASELINE" | "DOCKER_HOST_BASELINE";

function makeWorld(
  fixtures: Record<string, FixtureResponse>,
  profile: CloudProfile,
  opts: {
    targetType: "CONTAINER_IMAGE" | "KUBERNETES_CLUSTER" | "DOCKER_HOST";
    targetValue: string; targetHost: string; scope: typeof TEST_SCOPE;
    cloudFixtures?: InstanceType<typeof FakeStore>["cloudFixtures"];
    workerCapabilities?: string[];
  },
) {
  const deps = fixtureConnectorDeps();
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  const planCloud = createCloudNativeAdapters(new FixtureToolRunner(fixtures), deps);
  const planCode = createCodeAdapters(new FixtureToolRunner(fixtures));
  for (const a of [...planCloud, ...planCode]) planRegistry.register(a);
  const health = { ...cloudNativeHealthBySlug(planCloud), ...codeHealthBySlug(planCode) };
  if (opts.cloudFixtures?.clusterId) health["kubernetes-connector"] = "HEALTHY";
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: health,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: opts.targetType,
    networkTarget: { targetValue: opts.targetValue, targetHost: opts.targetHost, scope: opts.scope },
    ...(opts.cloudFixtures ? { cloudFixtures: opts.cloudFixtures } : {}),
  });
  const runner = new FixtureToolRunner(fixtures);
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createCloudNativeAdapters(runner, deps)) execRegistry.register(a);
  for (const a of createCodeAdapters(runner)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, {
    workerCapabilities: opts.workerCapabilities ?? [],
  });
  return { runner, store, dag: new DagRunner(store, executor) };
}

const IMAGE_FIXTURES: Record<string, FixtureResponse> = {
  trivy: { stdout: FIXTURE_TRIVY_OUTPUT, version: "0.58.0" },
  syft: { stdout: FIXTURE_SYFT_OUTPUT, version: "1.18.0" },
  grype: { stdout: FIXTURE_GRYPE_IMAGE_OUTPUT, version: "0.92.0" },
};

describe("Prompt 13 E2E — CONTAINER_BASELINE over the fixture image", () => {
  it("resolves, inventories, scans and correlates — Trivy+Grype merge on the digest (§20)", async () => {
    const { store, dag } = makeWorld(IMAGE_FIXTURES, "CONTAINER_BASELINE", {
      targetType: "CONTAINER_IMAGE", targetValue: FIXTURE_IMAGE_REF, targetHost: "registry.example.com", scope: IMAGE_SCOPE,
      cloudFixtures: { imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect([...store.stages.values()].every((s) => s === "COMPLETED")).toBe(true);
    expect(store.events.some((e) => e.type === "container.image_resolved")).toBe(true);
    expect(store.events.some((e) => e.type === "container.scan_completed")).toBe(true);
    expect(store.events.some((e) => e.type === "container.quality_gate_evaluated")).toBe(true);

    // Image identity + SBOM inventory (§5/§12/§13).
    expect(store.images.some((i) => i.digest === FIXTURE_IMAGE_DIGEST)).toBe(true);
    const purls = store.components.map((c) => c.purl);
    expect(purls).toContain("pkg:deb/debian/openssl@1.1.1n");
    expect(purls).toContain("pkg:npm/lodash@4.17.20");

    // §20: the shared openssl CVE is ONE canonical finding with two
    // sources; the full canonical set is exactly the five real issues.
    const canonical = store.correlatedFindings;
    const openssl = canonical.filter((f) => f.cve === "CVE-2023-0286");
    expect(openssl).toHaveLength(1);
    expect(openssl[0]?.sources.sort()).toEqual(["grype", "trivy"]);
    expect(openssl[0]?.imageDigest).toBe(FIXTURE_IMAGE_DIGEST);
    expect(canonical.map((f) => f.cve).filter(Boolean).sort()).toEqual(["CVE-2021-44228", "CVE-2022-0778", "CVE-2023-0286"]);
    expect(canonical.some((f) => f.controlId === "AVD-DS-0002" && f.origin === "STATIC_CONFIGURATION_FINDING")).toBe(true);

    // §18/§101: the secret is metadata-only — the fake value appears
    // NOWHERE in persisted store state.
    const secret = canonical.find((f) => f.secret);
    expect(secret?.secret?.detector).toBe("aws-access-key-id");
    expect(JSON.stringify(store)).not.toContain(FIXTURE_FAKE_IMAGE_SECRET);

    // §75: the gate FAILED (critical CVE + image secret) yet the scan
    // completed — the verdict is a result, not a pipeline crash (§82).
    expect(store.containerQualityGateRecord?.status).toBe("FAILED");
  });

  it("records tag→digest drift as a new snapshot, never an overwrite (§78)", async () => {
    const { store, dag } = makeWorld(IMAGE_FIXTURES, "CONTAINER_BASELINE", {
      targetType: "CONTAINER_IMAGE", targetValue: FIXTURE_IMAGE_REF, targetHost: "registry.example.com", scope: IMAGE_SCOPE,
      cloudFixtures: { imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST, previousDigest: FIXTURE_IMAGE_DIGEST_DRIFTED },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.events.some((e) => e.type === "container.image_drift_detected")).toBe(true);
    expect(store.imageSnapshots[0]?.drift).toBe(true);
    expect(store.imageSnapshots[0]?.previousDigest).toBe(FIXTURE_IMAGE_DIGEST_DRIFTED);
  });

  it("CONTAINER_MISCONFIG_ONLY produces static configuration findings (§16/§46)", async () => {
    const { store, dag } = makeWorld({
      trivy: { stdout: FIXTURE_TRIVY_OUTPUT, version: "0.58.0" },
      checkov: { stdout: FIXTURE_CHECKOV_OUTPUT, version: "3.2.0" },
    }, "CONTAINER_MISCONFIG_ONLY", {
      targetType: "CONTAINER_IMAGE", targetValue: FIXTURE_IMAGE_REF, targetHost: "registry.example.com", scope: IMAGE_SCOPE,
      cloudFixtures: { imageRef: FIXTURE_IMAGE_REF, imageDigest: FIXTURE_IMAGE_DIGEST },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.findings.some((f) => f.ruleId === "CKV_K8S_16" && f.origin === "STATIC_CONFIGURATION_FINDING")).toBe(true);
    expect(store.findings.some((f) => f.cve)).toBe(false); // misconfig-only: no CVE findings at all
  });
});

describe("Prompt 13 E2E — KUBERNETES_BASELINE over the fixture cluster inventory", () => {
  it("inventories + assesses posture; privileged benchmark denied on a general worker (§39)", async () => {
    const { store, dag } = makeWorld({
      kubescape: { stdout: FIXTURE_KUBESCAPE_OUTPUT, version: "3.0.0" },
      "kube-bench": { stdout: FIXTURE_KUBE_BENCH_OUTPUT, version: "0.9.0" },
    }, "KUBERNETES_BASELINE", {
      targetType: "KUBERNETES_CLUSTER", targetValue: "fixture-cluster", targetHost: "fixture-cluster", scope: CLUSTER_SCOPE,
      cloudFixtures: { clusterId: "cluster-1", clusterRef: "fixture-cluster" },
    });
    const result = await dag.run("scan-1");
    // kube-bench is executor-denied (no PRIVILEGED_HOST_ASSESSMENT) —
    // the posture stage degrades to PARTIAL, honestly (§39/§55).
    expect(result.status).toBe("PARTIAL");
    expect(store.workloads).toHaveLength(2);
    expect(store.events.some((e) => e.type === "kubernetes.inventory_recorded")).toBe(true);
    const denied = store.events.filter((e) => e.type === "policy.denied");
    expect(denied.some((e) => e.payload.reasonCode === "UNAVAILABLE_FOR_WORKER")).toBe(true);
    // Posture findings came from the connector + Kubescape.
    expect(store.findings.some((f) => f.controlId === "KSV-0014" && f.resourceName === "legacy-agent")).toBe(true);
    expect(store.findings.some((f) => f.controlId === "C-0057")).toBe(true);
    expect(store.findings.some((f) => f.controlId === "1.1.12")).toBe(false); // kube-bench never ran
    expect(store.controlAssessments.length).toBeGreaterThan(0);
    // §36: secret values were never in the payload — count only.
    expect(JSON.stringify(store)).not.toContain("Zml4dHVyZS");
  });

  it("with the privileged capability the CIS benchmark runs (§39)", async () => {
    const { store, dag } = makeWorld({
      kubescape: { stdout: FIXTURE_KUBESCAPE_OUTPUT, version: "3.0.0" },
      "kube-bench": { stdout: FIXTURE_KUBE_BENCH_OUTPUT, version: "0.9.0" },
    }, "KUBERNETES_BASELINE", {
      targetType: "KUBERNETES_CLUSTER", targetValue: "fixture-cluster", targetHost: "fixture-cluster", scope: CLUSTER_SCOPE,
      cloudFixtures: { clusterId: "cluster-1", clusterRef: "fixture-cluster" },
      workerCapabilities: ["PRIVILEGED_HOST_ASSESSMENT"],
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.findings.some((f) => f.controlId === "1.1.12" && f.origin === "LIVE_CLUSTER_FINDING")).toBe(true);
    expect(store.controlAssessments.some((a) => a.frameworkKey === "CIS_KUBERNETES" && a.controlId === "1.1.1" && a.status === "PASS")).toBe(true);
  });

  it("without a registered cluster the connector is NOT_CONFIGURED and stages degrade honestly (§34)", async () => {
    const { store, dag } = makeWorld({}, "KUBERNETES_BASELINE", {
      targetType: "KUBERNETES_CLUSTER", targetValue: "fixture-cluster", targetHost: "fixture-cluster", scope: CLUSTER_SCOPE,
      cloudFixtures: {},
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.workloads).toHaveLength(0);
    expect(store.events.some((e) => e.type === "policy.denied" && e.payload.reasonCode === "CLUSTER_NOT_CONFIGURED")).toBe(true);
  });
});

describe("Prompt 13 E2E — DOCKER_HOST_BASELINE (§28–§31)", () => {
  it("denied on a general worker; assessed on the privileged worker", async () => {
    const fixtures = { "docker-bench-security": { stdout: FIXTURE_DOCKER_BENCH_OUTPUT, version: "1.6.0" } };
    const deniedWorld = makeWorld(fixtures, "DOCKER_HOST_BASELINE", {
      targetType: "DOCKER_HOST", targetValue: "fixture-docker-host", targetHost: "fixture-docker-host",
      scope: { includeHosts: ["fixture-docker-host"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      cloudFixtures: { hostRef: "fixture-docker-host" },
    });
    const deniedResult = await deniedWorld.dag.run("scan-1");
    expect(deniedResult.status).toBe("PARTIAL");
    expect(deniedWorld.store.findings).toHaveLength(0);

    const world = makeWorld(fixtures, "DOCKER_HOST_BASELINE", {
      targetType: "DOCKER_HOST", targetValue: "fixture-docker-host", targetHost: "fixture-docker-host",
      scope: { includeHosts: ["fixture-docker-host"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      cloudFixtures: { hostRef: "fixture-docker-host" },
      workerCapabilities: ["PRIVILEGED_HOST_ASSESSMENT"],
    });
    const result = await world.dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(world.store.events.some((e) => e.type === "docker.posture_assessed")).toBe(true);
    expect(world.store.findings.some((f) => f.controlId === "4.1" && f.origin === "DOCKER_HOST_FINDING")).toBe(true);
    expect(world.store.controlAssessments.some((a) => a.frameworkKey === "CIS_DOCKER" && a.status === "PASS")).toBe(true);
  });
});

// Type-level guard: the connector import is part of the world wiring.
void KubernetesConnector;
