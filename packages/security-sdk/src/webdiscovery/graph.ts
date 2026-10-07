import type {
  NormalizedAsset, NormalizedEndpoint, NormalizedEndpointParameter, NormalizedService,
} from "../findings/finding.types";

/**
 * Endpoint graph (Prompt 6 §31): the relationship view later
 * vulnerability-testing stages consume —
 * Asset → Service → Endpoint → Parameter. Pure structure building over
 * normalized inventory; no inference, no guessed methods (§32).
 */

export type GraphNodeKind = "ASSET" | "SERVICE" | "ENDPOINT" | "PARAMETER";
export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
}
export interface GraphEdge {
  from: string;
  to: string;
  relation: "HOSTS" | "EXPOSES" | "HAS_PARAMETER";
}
export interface EndpointGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export function buildEndpointGraph(input: {
  assets: readonly NormalizedAsset[];
  services: readonly NormalizedService[];
  endpoints: readonly NormalizedEndpoint[];
  parameters?: readonly NormalizedEndpointParameter[];
}): EndpointGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const addNode = (node: GraphNode): string => {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
    return node.id;
  };
  const serviceIdByOrigin = new Map<string, string>();

  for (const asset of input.assets) {
    addNode({ id: `asset:${asset.host}`, kind: "ASSET", label: asset.host });
  }
  for (const svc of input.services) {
    const id = addNode({
      id: `service:${svc.host}:${svc.port}/${svc.protocol}`,
      kind: "SERVICE",
      label: `${svc.scheme ?? svc.protocol}://${svc.host}:${svc.port}`,
    });
    edges.push({ from: `asset:${svc.host}`, to: id, relation: "HOSTS" });
    const scheme = svc.scheme ?? (svc.port === 443 ? "https" : "http");
    serviceIdByOrigin.set(`${scheme}://${svc.host}${(scheme === "https" && svc.port === 443) || (scheme === "http" && svc.port === 80) ? "" : `:${svc.port}`}`, id);
  }
  const endpointIdByUrl = new Map<string, string>();
  for (const ep of input.endpoints) {
    let origin = "";
    let path = ep.url;
    try { const u = new URL(ep.url); origin = u.origin; path = u.pathname; } catch { /* keep raw */ }
    const id = addNode({
      id: `endpoint:${(ep.method ?? "GET").toUpperCase()} ${ep.url}`,
      kind: "ENDPOINT",
      label: `${(ep.method ?? "GET").toUpperCase()} ${path}`,
    });
    endpointIdByUrl.set(ep.url.split("?")[0]!, id);
    const serviceId = serviceIdByOrigin.get(origin);
    if (serviceId) edges.push({ from: serviceId, to: id, relation: "EXPOSES" });
  }
  for (const param of input.parameters ?? []) {
    const endpointId = endpointIdByUrl.get(param.endpointUrl.split("?")[0]!);
    if (!endpointId) continue;
    const id = addNode({
      id: `parameter:${param.endpointUrl}|${param.name}|${param.location}`,
      kind: "PARAMETER",
      label: `${param.name} (${param.location.toLowerCase()})`,
    });
    edges.push({ from: endpointId, to: id, relation: "HAS_PARAMETER" });
  }
  return { nodes: [...nodes.values()], edges };
}
