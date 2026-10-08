/**
 * Prompt 34 — recorded fixtures for V2 verification.
 *
 * Everything here is synthetic/recorded data (§163-style): fixture
 * provider responses, fixture RBAC inventory and a fixture Falco
 * event. The planted secret-shaped string in FIXTURE_RESOURCE_WITH_
 * SECRET exists to prove it is stripped before snapshot storage
 * (§147) — it is a fake canary, not a credential.
 */
import type { NormalizedCloudIdentity, NormalizedCloudResource } from "../findings/finding.types";
import type { CloudConnectionProbeFacts } from "./types";
import type { K8sRoleBindingRecord, K8sRoleRecord } from "./k8s";
import type { RuntimeEventFacts, RuntimeFindingFacts, RuntimeImageFacts, RuntimeWorkloadFacts } from "./falco";

export const FIXTURE_PROBE_CONNECTED: CloudConnectionProbeFacts = {
  credentialReferencePresent: true, secretResolvable: true, transportConfigured: true,
  reachable: true, authOutcome: "OK", identityAccountId: "123456789012", expectedAccountId: "123456789012",
};

export const FIXTURE_PROBE_LIMITED: CloudConnectionProbeFacts = {
  ...FIXTURE_PROBE_CONNECTED, missingPermissions: ["azure:Microsoft.Storage/storageAccounts/listKeys/action (metadata inventory)"],
};

export const FIXTURE_PROBE_CORE_LIMITED: CloudConnectionProbeFacts = {
  ...FIXTURE_PROBE_CONNECTED, missingPermissions: ["iam:ListUsers"], coreMissingPermissions: ["iam:ListUsers"],
};

export const FIXTURE_PROBE_AUTH_FAILED: CloudConnectionProbeFacts = {
  credentialReferencePresent: true, secretResolvable: true, transportConfigured: true,
  reachable: true, authOutcome: "AUTH_FAILED", expectedAccountId: "123456789012",
};

export const FIXTURE_PROBE_EXPIRED: CloudConnectionProbeFacts = { ...FIXTURE_PROBE_AUTH_FAILED, authOutcome: "EXPIRED" };

export const FIXTURE_PROBE_MISMATCH: CloudConnectionProbeFacts = {
  ...FIXTURE_PROBE_CONNECTED, identityAccountId: "999999999999",
};

export const FIXTURE_PROBE_NOT_CONFIGURED: CloudConnectionProbeFacts = {
  credentialReferencePresent: true, secretResolvable: true, transportConfigured: false, expectedAccountId: "123456789012",
};

const NOW = new Date("2026-10-08T00:00:00Z");

export const FIXTURE_IDENTITIES: NormalizedCloudIdentity[] = [
  {
    provider: "AWS", identityType: "ROLE", providerIdentityId: "arn:aws:iam::123456789012:role/app-role",
    name: "app-role", privileged: false, metadata: { accessibleResources: ["arn:aws:s3:::app-data"] },
  },
  {
    provider: "AWS", identityType: "ROLE", providerIdentityId: "arn:aws:iam::123456789012:role/admin-role",
    name: "admin-role", privileged: true, privilegeEvidence: { summary: "AdministratorAccess policy attached" },
    metadata: { attachedPolicies: ["arn:aws:iam::aws:policy/AdministratorAccess"] },
  },
  {
    provider: "AWS", identityType: "USER", providerIdentityId: "arn:aws:iam::123456789012:user/legacy-admin",
    name: "legacy-admin", privileged: true, mfaEnabled: false, keyAgeDays: 800,
    lastUsedAt: new Date(NOW.getTime() - 200 * 86_400_000).toISOString(),
    privilegeEvidence: { summary: "inline admin policy" }, metadata: {},
  },
  {
    provider: "AWS", identityType: "SERVICE_ACCOUNT", providerIdentityId: "arn:aws:iam::123456789012:role/web-workload",
    name: "web-workload", privileged: false,
    metadata: { assumesRoles: ["arn:aws:iam::123456789012:role/admin-role"], workloadRef: "prod/web" },
  },
];

export const FIXTURE_RESOURCES: NormalizedCloudResource[] = [
  {
    provider: "AWS", resourceType: "AWS_EC2_INSTANCE", providerResourceId: "arn:aws:ec2:us-east-1:123456789012:instance/i-web",
    name: "web-1", region: "us-east-1", tags: {}, exposure: "PUBLIC", source: "fixture",
    configuration: { attachedIdentityId: "arn:aws:iam::123456789012:role/web-workload", publicIp: true },
  },
  {
    provider: "AWS", resourceType: "AWS_S3_BUCKET", providerResourceId: "arn:aws:s3:::app-data",
    name: "app-data", region: "us-east-1", tags: { classification: "sensitive" }, exposure: "PRIVATE", source: "fixture",
    configuration: { encryption: "AES256", logging: true },
  },
  {
    provider: "AWS", resourceType: "AWS_RDS_INSTANCE", providerResourceId: "arn:aws:rds:us-east-1:123456789012:db:orders",
    name: "orders-db", region: "us-east-1", tags: {}, exposure: "PUBLIC", source: "fixture",
    configuration: { publiclyAccessible: true, encrypted: true, backupRetentionDays: 7 },
  },
];

/** §147 canary: a synthetic secret-shaped value planted in provider
 *  output — snapshot building must strip it before storage. */
export const FIXTURE_RESOURCE_WITH_SECRET: NormalizedCloudResource = {
  provider: "AWS", resourceType: "AWS_LAMBDA_FUNCTION", providerResourceId: "arn:aws:lambda:us-east-1:123456789012:function:api",
  name: "api-fn", region: "us-east-1", tags: {}, exposure: "PRIVATE", source: "fixture",
  configuration: {
    runtime: "nodejs20.x",
    environment: { API_KEY: "AKIAFAKECANARY000000", STAGE: "prod" },
    logging: true,
  },
};

export const FIXTURE_K8S_ROLES: K8sRoleRecord[] = [
  { kind: "ClusterRole", name: "wildcard-admin", rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }] },
  { kind: "Role", namespace: "prod", name: "secret-reader", rules: [{ apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"] }] },
  { kind: "Role", namespace: "prod", name: "deployer", rules: [{ apiGroups: ["apps"], resources: ["deployments"], verbs: ["get", "list", "watch"] }] },
];

export const FIXTURE_K8S_BINDINGS: K8sRoleBindingRecord[] = [
  {
    kind: "ClusterRoleBinding", name: "wildcard-binding", roleKind: "ClusterRole", roleName: "wildcard-admin",
    subjects: [{ kind: "ServiceAccount", name: "web-sa", namespace: "prod" }],
  },
  {
    kind: "RoleBinding", namespace: "prod", name: "deployer-binding", roleKind: "Role", roleName: "deployer",
    subjects: [{ kind: "ServiceAccount", name: "ci", namespace: "prod" }],
  },
];

export const FIXTURE_FALCO_EVENT: RuntimeEventFacts = {
  namespace: "prod", pod: "web-7d9c4b6f8-abc12", container: "web", rule: "Terminal shell in container", priority: "CRITICAL",
};

export const FIXTURE_RUNTIME_WORKLOADS: RuntimeWorkloadFacts[] = [
  { namespace: "prod", kind: "Deployment", name: "web", pods: ["web-7d9c4b6f8-abc12"], images: [{ container: "web", image: "ghcr.io/example/web", digest: "sha256:deadbeef" }] },
];

export const FIXTURE_RUNTIME_IMAGES: RuntimeImageFacts[] = [
  { id: "img-1", repository: "ghcr.io/example/web", digest: "sha256:deadbeef" },
];

export const FIXTURE_RUNTIME_FINDINGS: RuntimeFindingFacts[] = [
  { id: "find-1", imageDigest: "sha256:deadbeef", cve: "CVE-2024-0001", severity: "CRITICAL" },
];
