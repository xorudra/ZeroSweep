/**
 * Prompt 13 — YAML is hostile input (§49).
 *
 * Kubernetes manifests, Helm values and tool output arrive as
 * attacker-controlled YAML. Parsing discipline:
 *  - JSON_SCHEMA only — no custom tags, no object construction, no
 *    merge-key surprises beyond plain data (§49);
 *  - hard caps on bytes, document count, node count and depth —
 *    alias/billion-laughs style documents are rejected, not expanded;
 *  - plain data out (objects/arrays/strings/numbers/booleans/null).
 */
import { loadAll, JSON_SCHEMA } from "js-yaml";

export interface SafeYamlLimits {
  maxBytes: number;
  maxDocuments: number;
  maxNodes: number;
  maxDepth: number;
}

export const DEFAULT_YAML_LIMITS: SafeYamlLimits = {
  maxBytes: 2 * 1024 * 1024,
  maxDocuments: 500,
  maxNodes: 100_000,
  maxDepth: 40,
};

export class UnsafeYamlError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "UnsafeYamlError";
    this.code = code;
  }
}

function measure(value: unknown, limits: SafeYamlLimits, state: { nodes: number }, depth: number): void {
  if (depth > limits.maxDepth) throw new UnsafeYamlError("YAML_TOO_DEEP", `YAML exceeds maximum depth ${limits.maxDepth}`);
  state.nodes++;
  if (state.nodes > limits.maxNodes) throw new UnsafeYamlError("YAML_TOO_MANY_NODES", `YAML exceeds maximum node count ${limits.maxNodes}`);
  if (Array.isArray(value)) {
    for (const item of value) measure(item, limits, state, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) measure(v, limits, state, depth + 1);
  }
}

/** Parse multi-document YAML into plain data, or throw UnsafeYamlError.
 *  Custom tags (`!Ref`, `!!python/object`, ...) are rejected by the
 *  JSON schema; anchors are expanded by the parser but bounded by the
 *  node counter, so alias bombs fail closed. */
export function parseYamlDocuments(text: string, limits: SafeYamlLimits = DEFAULT_YAML_LIMITS): unknown[] {
  if (typeof text !== "string") throw new UnsafeYamlError("YAML_NOT_TEXT", "YAML input must be text");
  if (Buffer.byteLength(text, "utf8") > limits.maxBytes) {
    throw new UnsafeYamlError("YAML_TOO_LARGE", `YAML exceeds maximum size ${limits.maxBytes} bytes`);
  }
  let docs: unknown[];
  try {
    docs = loadAll(text, { schema: JSON_SCHEMA, json: false });
  } catch (err) {
    throw new UnsafeYamlError("YAML_INVALID", `YAML rejected: ${err instanceof Error ? err.message.split("\n")[0] : "parse error"}`);
  }
  if (docs.length > limits.maxDocuments) {
    throw new UnsafeYamlError("YAML_TOO_MANY_DOCUMENTS", `YAML exceeds maximum document count ${limits.maxDocuments}`);
  }
  const state = { nodes: 0 };
  for (const doc of docs) measure(doc, limits, state, 0);
  return docs;
}

/** Split a manifest bundle into Kubernetes object documents, skipping
 *  empty documents and Helm template files (which are not valid YAML
 *  until rendered — they are inventoried, never executed/rendered, §50). */
export function kubernetesDocuments(text: string, limits?: SafeYamlLimits): Record<string, unknown>[] {
  return parseYamlDocuments(text, limits)
    .filter((d): d is Record<string, unknown> => !!d && typeof d === "object" && !Array.isArray(d))
    .filter((d) => typeof d.kind === "string" && typeof d.apiVersion === "string");
}

/** Classify a source file as a cloud-native manifest (§48) purely from
 *  its path + a light content probe. Content is never executed. */
export function classifyManifestFile(path: string, contentSample = ""): "DOCKERFILE" | "KUBERNETES" | "HELM_CHART" | "HELM_VALUES" | "COMPOSE" | null {
  const base = path.split("/").pop() ?? path;
  if (/^Dockerfile(\..+)?$/i.test(base) || base.toLowerCase() === "dockerfile") return "DOCKERFILE";
  if (base === "Chart.yaml") return "HELM_CHART";
  if (/^values.*\.ya?ml$/i.test(base) && path.includes("charts/") === false) return "HELM_VALUES";
  if (/^docker-compose.*\.ya?ml$/i.test(base) || base === "compose.yaml" || base === "compose.yml") return "COMPOSE";
  if (/\.ya?ml$/i.test(base)) {
    if (/^kind:\s*(Deployment|StatefulSet|DaemonSet|Service|Ingress|ConfigMap|Secret|ServiceAccount|Role|ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy|Pod|Job|CronJob|Namespace|PersistentVolumeClaim)\b/m.test(contentSample)) return "KUBERNETES";
    if (path.includes("/templates/") && /(^|\/)charts?\//.test(path)) return "HELM_CHART";
  }
  return null;
}
