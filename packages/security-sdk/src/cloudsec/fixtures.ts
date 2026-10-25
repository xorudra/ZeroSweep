/**
 * Prompt 14 — recorded fixture payloads (§86/§90–§102).
 *
 * Obviously-fake accounts on documentation identities (account
 * 123456789012, example tenant/project ids, TEST-NET/documentation
 * naming). No fixture contains a real credential: the "keys" below
 * are fake FORMAT strings used to prove the platform never stores or
 * displays secret values (§100) — they are synthetic and invalid.
 */
import type { RawCloudInventory } from "./inventory";

export const FIXTURE_AWS_ACCOUNT_ID = "123456789012";
export const FIXTURE_AZURE_SUBSCRIPTION_ID = "00000000-0000-4000-8000-000000000001";
export const FIXTURE_GCP_PROJECT_ID = "zerosweep-fixture-project";

/** AWS fixture inventory (§90): public SG, S3 posture, IAM policy,
 *  logging gaps, EKS/ECR links, RDS/KMS/serverless/secret metadata. */
export const AWS_FIXTURE_INVENTORY: RawCloudInventory = {
  identity: { accountId: FIXTURE_AWS_ACCOUNT_ID, arn: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:root` },
  regions: ["us-east-1", "eu-west-1"],
  resources: [
    {
      type: "security_group", id: "sg-0fixture0001", name: "web-sg", region: "us-east-1",
      tags: { Name: "web-sg", Owner: "platform-team" },
      config: { ingress: [{ cidr: "0.0.0.0/0", fromPort: 22, toPort: 22, protocol: "tcp" }, { cidr: "0.0.0.0/0", fromPort: 443, toPort: 443, protocol: "tcp" }] },
    },
    {
      type: "s3_bucket", id: "arn:aws:s3:::public-assets-fixture", name: "public-assets-fixture", region: "us-east-1",
      tags: { DataClass: "public" },
      config: { publicAccess: true, publicAccessBlock: false, aclPublic: true, encryption: "PROVIDER_DEFAULT", logging: false, versioning: false },
    },
    {
      type: "s3_bucket", id: "arn:aws:s3:::private-data-fixture", name: "private-data-fixture", region: "us-east-1",
      config: { publicAccess: false, publicAccessBlock: true, aclPublic: false, encryption: "KMS", logging: true, versioning: true },
    },
    {
      type: "rds_instance", id: "arn:aws:rds:us-east-1:123456789012:db:orders-fixture", name: "orders-fixture", region: "us-east-1",
      config: { publicAccess: true, encryption: false, backupEnabled: false, tlsRequired: false },
    },
    {
      type: "kms_key", id: "arn:aws:kms:us-east-1:123456789012:key/fixture-key-1", name: "app-key-fixture", region: "us-east-1",
      config: { rotationEnabled: false, keyState: "Enabled" },
    },
    {
      type: "cloudtrail", id: "arn:aws:cloudtrail:us-east-1:123456789012:trail/main", name: "main-trail", region: "us-east-1",
      config: { enabled: false, multiRegion: false },
    },
    { type: "guardduty", id: "guardduty/us-east-1", name: "guardduty", region: "us-east-1", config: { enabled: false } },
    {
      type: "ec2_instance", id: "arn:aws:ec2:us-east-1:123456789012:instance/i-0fixture01", name: "web-1", region: "us-east-1",
      config: { publicIp: "203.0.113.10", identityRef: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:role/WebRole` },
    },
    {
      type: "lambda_function", id: "arn:aws:lambda:us-east-1:123456789012:function:exporter", name: "exporter", region: "us-east-1",
      config: { runtime: "python3.9", publicAccess: true, identityRef: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:role/ExporterRole`, envKeys: ["TABLE_NAME", "API_TOKEN"] },
    },
    {
      type: "eks_cluster", id: "arn:aws:eks:us-east-1:123456789012:cluster/prod-fixture", name: "prod-fixture", region: "us-east-1",
      config: { clusterName: "prod-fixture", version: "1.29", endpointPublicAccess: true },
    },
    {
      type: "ecr_repository", id: "arn:aws:ecr:us-east-1:123456789012:repository/api", name: "api", region: "us-east-1",
      config: { registryName: "api" },
    },
    {
      type: "secrets_manager_secret", id: "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds-fixture", name: "db-creds-fixture", region: "us-east-1",
      config: { rotationEnabled: false },
    },
  ],
  identities: [
    {
      type: "user", id: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:user/rudra-admin-fixture`, name: "rudra-admin-fixture",
      mfaEnabled: false, lastUsed: "2026-01-10T00:00:00Z",
      accessKeys: [{ ageDays: 540, status: "Active" }],
      attachedPolicies: [{
        name: "AdministratorAccess", document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] },
      }],
    },
    {
      type: "role", id: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:role/WebRole`, name: "WebRole",
      trustPolicy: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" }] },
      attachedPolicies: [{
        name: "S3Wildcard", document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }] },
      }],
    },
    {
      type: "role", id: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:role/ExporterRole`, name: "ExporterRole",
      trustPolicy: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] },
      attachedPolicies: [{ name: "ReadOnlyAccess" }],
    },
  ],
};

/** Azure fixture inventory (§91): NSG, storage, RBAC, AKS. */
export const AZURE_FIXTURE_INVENTORY: RawCloudInventory = {
  identity: { subscriptionId: FIXTURE_AZURE_SUBSCRIPTION_ID },
  regions: ["eastus"],
  resources: [
    {
      type: "nsg", id: `/subscriptions/${FIXTURE_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-fixture/providers/Microsoft.Network/networkSecurityGroups/web-nsg`,
      name: "web-nsg", region: "eastus",
      config: { ingress: [{ cidr: "*", fromPort: 3389, toPort: 3389, protocol: "tcp" }] },
    },
    {
      type: "storage_account", id: `/subscriptions/${FIXTURE_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-fixture/providers/Microsoft.Storage/storageAccounts/fixturedata`,
      name: "fixturedata", region: "eastus",
      config: { publicAccess: true, encryption: "KMS", logging: true, versioning: true },
    },
    {
      type: "sql_server", id: `/subscriptions/${FIXTURE_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-fixture/providers/Microsoft.Sql/servers/sql-fixture`,
      name: "sql-fixture", region: "eastus",
      config: { publicAccess: true, encryption: "KMS", backupEnabled: true, tlsRequired: true },
    },
    {
      type: "aks_cluster", id: `/subscriptions/${FIXTURE_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-fixture/providers/Microsoft.ContainerService/managedClusters/aks-fixture`,
      name: "aks-fixture", region: "eastus",
      config: { clusterName: "aks-fixture", version: "1.29", endpointPublicAccess: true },
    },
    { type: "activity_log", id: "activity-log-fixture", name: "activity-log", region: "eastus", config: { enabled: true, multiRegion: true } },
    { type: "key_vault", id: `/subscriptions/${FIXTURE_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-fixture/providers/Microsoft.KeyVault/vaults/kv-fixture`, name: "kv-fixture", region: "eastus", config: { rotationEnabled: true } },
  ],
  identities: [
    {
      type: "user", id: "entra-user-fixture-1", name: "rudra-fixture@example.com", mfaEnabled: false,
      attachedPolicies: [{ name: "Owner" }],
    },
    {
      type: "role", id: "entra-role-owner", name: "Owner", privileged: true,
      privilegeEvidence: { scope: "subscription", note: "fixture RBAC assignment" },
      attachedPolicies: [],
    },
  ],
};

/** GCP fixture inventory (§92): firewall, storage, IAM, GKE. */
export const GCP_FIXTURE_INVENTORY: RawCloudInventory = {
  identity: { projectId: FIXTURE_GCP_PROJECT_ID },
  regions: ["us-central1"],
  resources: [
    {
      type: "firewall_rule", id: `projects/${FIXTURE_GCP_PROJECT_ID}/global/firewalls/allow-ssh-world`, name: "allow-ssh-world", region: "us-central1",
      config: { ingress: [{ cidr: "0.0.0.0/0", fromPort: 22, toPort: 22, protocol: "tcp" }] },
    },
    {
      type: "storage_bucket", id: `projects/${FIXTURE_GCP_PROJECT_ID}/buckets/public-fixture-bucket`, name: "public-fixture-bucket", region: "us-central1",
      config: { publicAccess: true, encryption: "KMS", logging: false, versioning: true },
    },
    {
      type: "sql_instance", id: `projects/${FIXTURE_GCP_PROJECT_ID}/instances/sql-fixture`, name: "sql-fixture", region: "us-central1",
      config: { publicAccess: false, encryption: "KMS", backupEnabled: true, tlsRequired: true },
    },
    {
      type: "gke_cluster", id: `projects/${FIXTURE_GCP_PROJECT_ID}/locations/us-central1/clusters/gke-fixture`, name: "gke-fixture", region: "us-central1",
      config: { clusterName: "gke-fixture", version: "1.29", endpointPublicAccess: true },
    },
    { type: "logging_config", id: "logging-fixture", name: "cloud-audit-logs", region: "us-central1", config: { enabled: true, multiRegion: true } },
  ],
  identities: [
    {
      type: "service_account", id: `fixture-sa@${FIXTURE_GCP_PROJECT_ID}.iam.gserviceaccount.com`, name: "fixture-sa",
      privileged: true, privilegeEvidence: { role: "roles/owner" },
      attachedPolicies: [{ name: "roles/owner" }],
    },
    {
      type: "user", id: "rudra-fixture@example.com", name: "rudra-fixture@example.com", mfaEnabled: true,
      attachedPolicies: [{ name: "roles/viewer" }],
    },
  ],
};

/** Prowler fixture (§90): one FAIL (same public bucket as native
 *  analysis → canonical merge), one PASS (never a finding, §23). */
export const PROWLER_FIXTURE = [
  {
    CheckID: "s3_bucket_public_access", CheckTitle: "S3 bucket public access", Status: "FAIL", Severity: "high",
    ServiceName: "s3", Region: "us-east-1", ResourceArn: "arn:aws:s3:::public-assets-fixture",
    AccountId: FIXTURE_AWS_ACCOUNT_ID, Description: "Bucket allows public access.",
  },
  {
    CheckID: "s3_bucket_default_encryption", CheckTitle: "S3 default encryption", Status: "PASS", Severity: "medium",
    ServiceName: "s3", Region: "us-east-1", ResourceArn: "arn:aws:s3:::private-data-fixture", AccountId: FIXTURE_AWS_ACCOUNT_ID,
  },
  {
    CheckID: "iam_user_mfa_enabled", CheckTitle: "IAM user MFA", Status: "FAIL", Severity: "medium",
    ServiceName: "iam", Region: "us-east-1", ResourceArn: `arn:aws:iam::${FIXTURE_AWS_ACCOUNT_ID}:user/rudra-admin-fixture`,
    AccountId: FIXTURE_AWS_ACCOUNT_ID,
  },
];

/** ScoutSuite fixture (§90): same public bucket flagged (§60 merge). */
export const SCOUTSUITE_FIXTURE = {
  services: {
    s3: {
      findings: {
        "s3-bucket-public-access": {
          description: "S3 bucket allows public access", level: "danger",
          items: [{ id: "arn:aws:s3:::public-assets-fixture", region: "us-east-1" }],
        },
      },
    },
  },
};

/** Steampipe fixture rows (§32): alarm + ok rows. */
export const STEAMPIPE_FIXTURE_ROWS = [
  { control_id: "cis_v150_2_1_2", title: "S3 public access blocked", status: "alarm", resource: "arn:aws:s3:::public-assets-fixture", region: "us-east-1", service: "s3", reason: "public access block not configured", severity: "high" },
  { control_id: "cis_v150_3_1", title: "CloudTrail enabled", status: "ok", resource: "main-trail", region: "us-east-1", service: "cloudtrail", reason: "trail enabled" },
];

/** ROADtools fixture (§91): privileged Entra role assignment. */
export const ROADTOOLS_FIXTURE = {
  role_assignments: [{ principal: "entra-user-fixture-1", role: "Global Administrator" }],
  applications: [{ id: "app-fixture-1", name: "sync-app", permissions: [{ name: "RoleManagement.ReadWrite.Directory" }] }],
};

/** Checkov fixture for IaC/live correlation (§96): CKV_AWS_53 on the
 *  SAME bucket the live inventory reports public. The resource label
 *  matches the deployed name — the reliable-identity case (§62). */
export const CHECKOV_IAC_FIXTURE = {
  results: {
    passed_checks: [],
    failed_checks: [{
      check_id: "CKV_AWS_53",
      check_name: "Ensure S3 bucket has block public policy enabled",
      resource: "aws_s3_bucket.fixture.public-assets-fixture",
      file_path: "/main.tf",
      file_line_range: [1, 12],
    }],
    skipped_checks: [],
    parsing_errors: [],
  },
};

/** A fixture "leaked credential" scenario (§100): an inventory payload
 *  that (incorrectly) carries secret-shaped material in a tag/config.
 *  The platform must fingerprint/redact it — never store the value. */
export const HOSTILE_SECRET_FIXTURE: RawCloudInventory = {
  regions: ["us-east-1"],
  resources: [{
    type: "s3_bucket", id: "arn:aws:s3:::tagged-fixture", name: "tagged-fixture", region: "us-east-1",
    tags: { Owner: "platform-team", Note: "key is AKIAIOSFODNN7EXAMPLE and secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
    config: { publicAccess: false, encryption: "KMS" },
  }],
  identities: [],
};
