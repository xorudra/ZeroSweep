/**
 * Prompt 34 — container image policy (§62) and IaC security identity /
 * evidence handling (§65–§69).
 *
 * Image policy evaluates METADATA the platform already holds —
 * registry, tag, digest, image config summary and vulnerability
 * summary. It never pulls, runs or modifies an image. IaC evidence
 * snippets are sanitized before storage: secrets embedded in source
 * are redacted, never exposed (§69).
 */
import { createHash } from "node:crypto";
import { redactSecretShapes } from "../cloudsec/guards";
import { IAC_RULE_TO_LIVE_RULE } from "../cloudsec/correlation";

export interface ImagePolicyInput {
  registry: string;
  repository: string;
  tag?: string | null;
  digest?: string | null;
  /** Image config summary as stored on ContainerImageSnapshot. */
  config?: { user?: string; healthcheckPresent?: boolean; signed?: boolean };
  worstSeverity?: string | null; // CRITICAL | HIGH | MEDIUM | LOW | null
  kevCount?: number;
}

export interface ImagePolicyDefinition {
  approvedRegistries: string[];
  forbidLatestTag: boolean;
  requireDigestPin: boolean;
  forbidRootUser: boolean;
  requireHealthcheck: boolean;
  requireSignedMetadata: boolean;
  /** Highest tolerated vulnerability severity present in the image. */
  maxSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

export const DEFAULT_IMAGE_POLICY: ImagePolicyDefinition = {
  approvedRegistries: [],
  forbidLatestTag: true,
  requireDigestPin: false,
  forbidRootUser: true,
  requireHealthcheck: false,
  requireSignedMetadata: false,
};

export interface ImagePolicyViolation {
  rule: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  detail: string;
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

/** §62: evaluate one image against the image policy. */
export function evaluateImagePolicy(image: ImagePolicyInput, policy: ImagePolicyDefinition): {
  compliant: boolean;
  violations: ImagePolicyViolation[];
} {
  const violations: ImagePolicyViolation[] = [];
  if (policy.approvedRegistries.length > 0 && !policy.approvedRegistries.includes(image.registry)) {
    violations.push({ rule: "approved-registry", severity: "HIGH", detail: `Registry ${image.registry} is not in the approved registry list (§62).` });
  }
  if (policy.forbidLatestTag && (!image.tag || image.tag === "latest")) {
    violations.push({ rule: "latest-tag", severity: "MEDIUM", detail: "Image uses the mutable \"latest\" tag (or no tag) — tags are mutable metadata, digest is identity (§49/§62)." });
  }
  if (policy.requireDigestPin && !image.digest) {
    violations.push({ rule: "digest-pin", severity: "MEDIUM", detail: "Image is not pinned by digest (§49/§62)." });
  }
  const user = image.config?.user;
  if (policy.forbidRootUser && (user === undefined || user === "" || user === "root" || user === "0")) {
    violations.push({ rule: "root-user", severity: "HIGH", detail: `Image runs as root (user=${user ?? "unset"}) per config metadata (§62).` });
  }
  if (policy.requireHealthcheck && image.config?.healthcheckPresent !== true) {
    violations.push({ rule: "healthcheck", severity: "LOW", detail: "No healthcheck metadata present in image config (§62)." });
  }
  if (policy.requireSignedMetadata && image.config?.signed !== true) {
    violations.push({ rule: "signed-image", severity: "MEDIUM", detail: "No signed-image metadata recorded for this image (§62)." });
  }
  if (policy.maxSeverity && image.worstSeverity) {
    if ((SEVERITY_RANK[image.worstSeverity] ?? 0) > (SEVERITY_RANK[policy.maxSeverity] ?? 0)) {
      violations.push({ rule: "vulnerability-ceiling", severity: "HIGH", detail: `Image contains ${image.worstSeverity} vulnerabilities, above the policy ceiling ${policy.maxSeverity} (§62).` });
    }
  }
  if ((image.kevCount ?? 0) > 0) {
    violations.push({ rule: "kev-present", severity: "HIGH", detail: `Image carries ${image.kevCount} KEV-listed vulnerabilit(ies) — prioritized by Risk Engine V3 (§59).` });
  }
  return { compliant: violations.length === 0, violations };
}

/* ------------------------------ IaC (§65–§69) ------------------------------ */

export interface IacFindingIdentityInput {
  repository: string;
  filePath: string;
  resource: string;
  ruleId: string;
  lineStart?: number;
  lineEnd?: number;
  commit?: string;
}

/**
 * §67: IaC finding identity — repository + file + resource + rule +
 * stable code location. The fingerprint survives line drift within
 * the same resource block by keying on the resource, while the
 * location is preserved as evidence (§68).
 */
export function iacFindingIdentity(input: IacFindingIdentityInput): { identity: string; fingerprint: string } {
  const identity = [input.repository, input.filePath, input.resource, input.ruleId].join("::");
  const fingerprint = `iac:${createHash("sha256").update(identity.toLowerCase()).digest("hex")}`;
  return { identity, fingerprint };
}

/** §68/§69: evidence for an IaC finding — sanitized snippet only.
 *  Secret-shaped assignments are redacted; the snippet is bounded. */
export function sanitizeIacEvidence(input: IacFindingIdentityInput & { snippet?: string }): {
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
  resource: string;
  ruleId: string;
  commit?: string;
  snippet?: string;
  liveRuleId?: string;
} {
  const snippet = input.snippet ? redactSecretShapes(input.snippet).slice(0, 400) : undefined;
  return {
    filePath: input.filePath,
    ...(input.lineStart !== undefined ? { lineStart: input.lineStart } : {}),
    ...(input.lineEnd !== undefined ? { lineEnd: input.lineEnd } : {}),
    resource: input.resource,
    ruleId: input.ruleId,
    ...(input.commit ? { commit: input.commit } : {}),
    ...(snippet ? { snippet } : {}),
    ...(IAC_RULE_TO_LIVE_RULE[input.ruleId] ? { liveRuleId: IAC_RULE_TO_LIVE_RULE[input.ruleId] } : {}),
  };
}

/** §65: IaC formats the IaCSecurityService governs (Checkov-supported
 *  set already integrated by Prompts 12/13 — V2 adds no new parser). */
export const IAC_SUPPORTED_FORMATS = [
  "TERRAFORM", "CLOUDFORMATION", "KUBERNETES_YAML", "DOCKERFILE", "HELM", "ARM", "BICEP", "SERVERLESS",
] as const;
